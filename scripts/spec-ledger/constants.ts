export const REQ_ID_PATTERN = /^(FR|NFR|SEC)-\d{3}$/;
export const REQ_FILE_PATTERN = /^(FR|NFR|SEC)-\d{3}\.md$/;
export const PACKAGE_SCOPE_PATTERN = /^(apps|packages)\/[a-zA-Z0-9._-]+$/;
export const EVENT_FILE_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z-[a-z0-9-]+-(FR|NFR|SEC)-\d{3}\.md$/;
export const CLAIM_FILE_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z-[a-z0-9-]+-claim-(FR|NFR|SEC)-\d{3}\.md$/;
export const ALLOWED_REQ_STATUS = new Set(["Proposed", "In Progress", "Done"]);
export const ALLOWED_CHANGE_TYPE = new Set(["propose", "implement", "verify", "decision", "status-update", "claim"]);
export const ALLOWED_CLAIM_ACTION = new Set(["claim", "heartbeat", "release", "override"]);

export const REQUIRED_ARCHITECTURE_DOCS = [
	"spec/ARCHITECTURE/README.md",
	"spec/ARCHITECTURE/current-infrastructure.md",
	"spec/ARCHITECTURE/ARD-0001-system-context.md",
	"spec/DECISIONS/ADR-0001-template.md",
];
