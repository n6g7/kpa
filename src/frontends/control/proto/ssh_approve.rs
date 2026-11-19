//! `ssh_approve`: approve one of the requests `ssh_pending` listed
//! (`docs/ssh-agent.md` § 6.8). The approval is the one the request would
//! have been given on screen, for the same scope.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::error::{ErrorCode, ErrorFields};

/// What `{"op":"ssh_approve", ...}` carries; `Op::SshApprove` wraps it.
///
/// A request is named by the random id `ssh_pending` gave it, not by what
/// it asked for. The id means nothing once the request is gone, which a
/// counter would not: after a lock it could name some other request. It
/// also says nothing of the scope the approval covers, so that can grow
/// (a forwarded request's) without this changing. One that doesn't parse is
/// a malformed request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshApproveRequest {
    pub id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshApproveError {
    /// No request has that id: it expired, a lock dropped it, or it never
    /// named one.
    NotPending,
}

impl SshApproveError {
    pub(super) fn fields(&self) -> ErrorFields<'_> {
        let SshApproveError::NotPending = self;
        ErrorFields::new(ErrorCode::NotPending)
            .detail("no such request is pending; it may have expired or the database locked")
    }
}
