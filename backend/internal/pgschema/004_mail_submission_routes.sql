-- Route registration belongs to the original submission, separately from its
-- final mail RPC. Null is an older record or an unstarted stage, not a retry.
ALTER TABLE space.send_submissions
 ADD COLUMN route_outcome text CHECK (route_outcome IN ('accepted','rejected','not_sent','unknown')),
 ADD COLUMN route_envelope bytea,
 ADD CONSTRAINT submission_route_document CHECK ((route_outcome IS NULL) = (route_envelope IS NULL)),
 ADD CONSTRAINT submission_route_context CHECK (route_outcome IS NULL OR context_key IS NOT NULL);
CREATE UNIQUE INDEX submissions_unresolved_route ON space.send_submissions(context_key)
 WHERE route_outcome='unknown' AND NOT query_only;
ALTER TABLE space.send_submissions DROP CONSTRAINT send_submissions_reference_kind_check;
ALTER TABLE space.send_submissions ADD CONSTRAINT send_submissions_reference_kind_check
 CHECK (reference_kind IN ('incoming','bootstrap_seed','hme_route'));

-- Locate the original unnamed three-column constraint by its exact columns;
-- PostgreSQL truncates automatically generated constraint names to 63 bytes.
DO $$
DECLARE original_name text;
BEGIN
 SELECT c.conname INTO STRICT original_name FROM pg_catalog.pg_constraint c
 WHERE c.conrelid='space.compose_contexts'::regclass AND c.contype='u'
 AND c.conkey=ARRAY[
  (SELECT attnum FROM pg_catalog.pg_attribute WHERE attrelid=c.conrelid AND attname='address_id'),
  (SELECT attnum FROM pg_catalog.pg_attribute WHERE attrelid=c.conrelid AND attname='route_recipient'),
  (SELECT attnum FROM pg_catalog.pg_attribute WHERE attrelid=c.conrelid AND attname='route_fingerprint')
 ]::smallint[];
 EXECUTE pg_catalog.format('ALTER TABLE space.compose_contexts DROP CONSTRAINT %I',original_name);
END $$;
CREATE UNIQUE INDEX compose_contexts_active_route ON space.compose_contexts(address_id,route_recipient,route_fingerprint)
 WHERE NOT COALESCE(NOT query_only AND state='failed' AND
  ((append_outcome IN ('not_sent','rejected') AND seed_outcome IS NULL)
   OR (append_outcome='accepted' AND seed_outcome IN ('not_sent','rejected'))),false);
