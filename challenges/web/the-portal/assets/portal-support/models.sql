CREATE TABLE document_version (id TEXT PRIMARY KEY, document_id TEXT, digest TEXT, content BLOB);
CREATE TABLE collection (id TEXT PRIMARY KEY, author TEXT, revision INTEGER, member_document TEXT);
CREATE TABLE workspace_reference (id TEXT PRIMARY KEY, collection_id TEXT);
CREATE TABLE preview (id TEXT PRIMARY KEY, reference_id TEXT, version_id TEXT, digest TEXT);
CREATE TABLE approval (id TEXT PRIMARY KEY, preview_id TEXT, signature TEXT);
CREATE TABLE export_job (id TEXT PRIMARY KEY, reference_id TEXT, approval_id TEXT, state TEXT, delivery_cursor INTEGER);
