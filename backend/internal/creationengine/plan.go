package creationengine

import (
	"crypto/rand"
	"math"
	"math/big"
	"sort"
)

// Plan fixes the first instant and, for multiple slots, the last at +one hour.
// Sorted independent offsets distribute the remaining slack without rejection
// loops. Every adjacent pair is at least five minutes apart.
func Plan(first int64, count int, random Random) ([]int64, error) {
	if count < 1 || count > MaximumAttempts || random == nil {
		return nil, ErrInvalid
	}
	if count == 1 {
		return []int64{first}, nil
	}
	last, err := add(first, int64(RoundDuration))
	if err != nil {
		return nil, err
	}
	slack := int64(RoundDuration) - int64(count-1)*int64(MinimumInterval)
	offsets := make([]int64, count-2)
	for i := range offsets {
		value, err := random(slack + 1)
		if err != nil || value < 0 || value > slack {
			return nil, ErrInvalid
		}
		offsets[i] = value
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	slots := make([]int64, count)
	slots[0], slots[count-1] = first, last
	for i, offset := range offsets {
		slots[i+1] = first + int64(i+1)*int64(MinimumInterval) + offset
	}
	return slots, nil
}

func secureRandom(upper int64) (int64, error) {
	if upper < 1 {
		return 0, ErrInvalid
	}
	value, err := rand.Int(rand.Reader, big.NewInt(upper))
	if err != nil {
		return 0, err
	}
	return value.Int64(), nil
}
func add(value, delta int64) (int64, error) {
	if delta > 0 && value > math.MaxInt64-delta || delta < 0 && value < math.MinInt64-delta {
		return 0, ErrInvalid
	}
	return value + delta, nil
}
func nextRevision(revision int64) (int64, error) {
	if revision < 0 || revision == math.MaxInt64 {
		return 0, ErrInvalid
	}
	return revision + 1, nil
}
func (e *Engine) plan(first int64, count int) ([]int64, error) {
	e.randomMu.Lock()
	defer e.randomMu.Unlock()
	return Plan(first, count, e.options.Random)
}
