package apple

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

type MailUpload struct {
	Filename, MediaType string
	Size                int64
	SHA256              [32]byte
	Body                io.Reader
}
type countedUpload struct {
	reader io.Reader
	count  int64
}

func (r *countedUpload) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.count += int64(n)
	return n, err
}
func (c *Client) validPartURL(raw string) bool {
	if !field(raw, 8192, true) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	if u.IsAbs() {
		if u.Scheme != "https" || u.Host != strings.TrimPrefix(c.document.Services.Mail, "https://") {
			return false
		}
	} else if u.Host != "" {
		return false
	}
	return (u.Path == "/wm/messagepart" || strings.HasPrefix(u.Path, "/wm/messagepart/")) && path.Clean(u.Path) == u.Path
}

// MailUploadPart uses the observed legacy File/Blob request: raw bytes with
// Apple's multipart/form-data header, without inventing a multipart wrapper.
// This uploads once and never follows a redirect or fetches a remote URL.
func (c *Client) MailUploadPart(ctx context.Context, input MailUpload) (MailPart, error) {
	const operation = "mail_upload"
	if input.Body == nil || input.Size < 0 || input.Size > 10<<20 || !field(input.Filename, 255, true) || strings.ContainsAny(input.Filename, "/\\") {
		return MailPart{}, invalid(operation)
	}
	media, _, err := mime.ParseMediaType(input.MediaType)
	if err != nil || media == "" {
		return MailPart{}, invalid(operation)
	}
	if err = c.lock(ctx); err != nil {
		return MailPart{}, err
	}
	defer c.unlock()
	endpoint, err := c.mailEndpoint("/wm/messagepart", false)
	if err != nil {
		return MailPart{}, err
	}
	var entropy [16]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		return MailPart{}, invalid(operation)
	}
	id := hex.EncodeToString(entropy[:])
	u, _ := url.Parse(endpoint)
	q := u.Query()
	q.Set("X-id", id)
	q.Set("X-type", input.MediaType)
	q.Set("X-size", strconv.FormatInt(input.Size, 10))
	q.Set("X-name", input.Filename)
	u.RawQuery = q.Encode()
	if !allowedRequest(u, c.document.Principal.Region) {
		return MailPart{}, invalid(operation)
	}
	hash := sha256.New()
	stream := &countedUpload{reader: io.TeeReader(io.LimitReader(input.Body, input.Size+1), hash)}
	trace := &sendTrace{}
	request, err := http.NewRequestWithContext(trace.context(ctx), http.MethodPost, u.String(), io.NopCloser(stream))
	if err != nil {
		return MailPart{}, invalid(operation)
	}
	request.ContentLength = input.Size
	if input.Size == 0 {
		request.Body = http.NoBody
	}
	request.GetBody = nil
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "multipart/form-data")
	request.Header.Set("X-channel", "XHR")
	request.Header.Set("X-File-Name", strings.ReplaceAll(url.QueryEscape(input.Filename), "+", "%20"))
	request.Header.Set("X-File-Size", strconv.FormatInt(input.Size, 10))
	request.Header.Set("Origin", homeOrigin(c.document.Principal.Region))
	request.Header.Set("Referer", homeOrigin(c.document.Principal.Region)+"/")
	request.Header.Set("User-Agent",serviceUserAgent)
	for _, cookie := range c.jar.Cookies(u) {
		request.AddCookie(cookie)
	}
	uploadClient := *c.http
	uploadClient.Timeout = 180 * time.Second
	response, err := uploadClient.Do(request)
	if err != nil {
		return MailPart{}, networkError(operation, err, true, trace.sent.Load())
	}
	defer response.Body.Close()
	if err = c.receiveCookies(u, response.Cookies(), time.Now()); err != nil {
		return MailPart{}, &Error{Kind: ResponseBudget, Operation: operation, Status: response.StatusCode, Unknown: true}
	}
	result := exchangeResult{status: response.StatusCode, header: response.Header.Clone()}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return MailPart{}, &Error{Kind: Redirect, Operation: operation, Status: response.StatusCode, Unknown: true}
	}
	result.body, err = io.ReadAll(io.LimitReader(response.Body, c.responseBytes+1))
	if err != nil {
		return MailPart{}, networkError(operation, err, true, true)
	}
	if int64(len(result.body)) > c.responseBytes {
		return MailPart{}, &Error{Kind: ResponseBudget, Operation: operation, Unknown: true}
	}
	if err = diagnose(operation, result, true); err != nil {
		return MailPart{}, err
	}
	media, _, err = mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" && media != "text/json" || uniqueJSON(result.body) != nil {
		return MailPart{}, &Error{Kind: MalformedResponse, Operation: operation, Unknown: true}
	}
	var descriptor struct {
		Status *json.Number `json:"status"`
		UID    string       `json:"uid"`
		URL    string       `json:"url"`
		Part   struct {
			Type      string `json:"type"`
			GUID      string `json:"guid"`
			Name      string `json:"name"`
			Filename  string `json:"filename"`
			URL       string `json:"url"`
			Size      int64  `json:"size"`
			MediaType string `json:"datatype"`
			Encoding  string `json:"encoding"`
		} `json:"msgPart"`
	}
	if json.Unmarshal(result.body, &descriptor) != nil || descriptor.Status == nil || descriptor.UID == "" || descriptor.Part.Type != "CoreMail.MessagePart" || descriptor.Part.Encoding == "" || !field(descriptor.Part.GUID, 512, true) || !strings.HasPrefix(descriptor.Part.GUID, "cachedpart:") || descriptor.Part.Name != input.Filename || descriptor.Part.Filename != input.Filename || descriptor.Part.Size != input.Size || !c.validPartURL(descriptor.Part.URL) || descriptor.URL != descriptor.Part.URL || stream.count != input.Size || subtle.ConstantTimeCompare(hash.Sum(nil), input.SHA256[:]) != 1 {
		return MailPart{}, &Error{Kind: MalformedResponse, Operation: operation, Code: "PART_DESCRIPTOR", Unknown: true}
	}
	actual, _, err := mime.ParseMediaType(descriptor.Part.MediaType)
	expected, _, _ := mime.ParseMediaType(input.MediaType)
	if err != nil || !strings.EqualFold(actual, expected) {
		return MailPart{}, &Error{Kind: MalformedResponse, Operation: operation, Code: "PART_TYPE", Unknown: true}
	}
	part := MailPart{GUID: descriptor.Part.GUID, Name: input.Filename, URL: descriptor.Part.URL, Size: input.Size, MediaType: descriptor.Part.MediaType}
	base, _ := url.Parse(c.document.Services.Mail)
	partURL, _ := url.Parse(part.URL)
	if values := partURL.Query()["guid"]; len(values) != 1 || values[0] != part.GUID {
		return MailPart{}, &Error{Kind: MalformedResponse, Operation: operation, Code: "PART_URL", Unknown: true}
	}
	part.URL = base.ResolveReference(partURL).String()
	if strings.HasPrefix(part.GUID, "cachedpart:") {
		cid := part.GUID
		part.ContentID = &cid
	}
	return part, nil
}
