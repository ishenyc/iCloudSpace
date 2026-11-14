-- Exact retained-entry receive-time projection; no-entry addresses stay NULL.
ALTER TABLE space.private_addresses ADD COLUMN latest_received_at space.instant_ns;

UPDATE space.private_addresses AS a
SET latest_received_at = received.latest_received_at
FROM (
    SELECT e.source_id, e.address_id, MAX(m.received_at) AS latest_received_at
    FROM space.mailbox_entries AS e
    JOIN space.source_messages AS m ON m.source_id = e.source_id AND m.id = e.message_id
    GROUP BY e.source_id, e.address_id
) AS received
WHERE a.source_id = received.source_id AND a.id = received.address_id;
