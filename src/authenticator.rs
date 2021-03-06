use pam_sys::{acct_mgmt, authenticate, close_session, end, open_session, putenv, setcred, start};
use pam_sys::{PamFlag, PamHandle, PamReturnCode};

use std::ptr;

use crate::{
    env::get_pam_env, env::PamEnvList, ffi, ConversationHandler, Converse, PamError, PamResult,
    PasswordConv,
};

/// Main struct to authenticate a user
///
/// You need to create an instance of it to start an authentication process. If you
/// want a simple password-based authentication, you can use `Authenticator::with_password`,
/// and to the following flow:
///
/// ```no_run
/// use pam::Authenticator;
///
/// let mut authenticator = Authenticator::with_password("system-auth")
///         .expect("Failed to init PAM client.");
/// // Preset the login & password we will use for authentication
/// authenticator.handler_mut().set_credentials("login", "password").unwrap();
/// // actually try to authenticate:
/// authenticator.authenticate().expect("Authentication failed!");
/// // Now that we are authenticated, it's possible to open a sesssion:
/// authenticator.open_session().expect("Failed to open a session!");
/// ```
///
/// If you wish to customise the PAM conversation function, you should rather create your
/// authenticator with `Authenticator::with_handler`, providing a struct implementing the
/// `Converse` trait. You can then mutably access your conversation handler using the
/// `Authenticator::handler_mut` method.
///
/// By default, the `Authenticator` will close any opened session when dropped. If you don't
/// want this, you can change its `close_on_drop` field to `False`.
pub struct Authenticator<'a, C: Converse<'a>> {
    /// Flag indicating whether the Authenticator should close the session on drop
    pub close_on_drop: bool,
    handler: C::Handler,
    is_authenticated: bool,
    has_open_session: bool,
    last_code: PamReturnCode,
}

impl<'a> Authenticator<'a, PasswordConv> {
    /// Create a new `Authenticator` with a given service name and a password-based conversation
    pub fn with_password(service: &str) -> PamResult<Authenticator<'a, PasswordConv>> {
        Authenticator::with_handler(service, PasswordConv::new())
    }
}

impl<'a, C: Converse<'a>> Authenticator<'a, C> {
    /// Creates a new Authenticator with a given service name and conversation callback
    pub fn with_handler(service: &str, converse: C) -> PamResult<Authenticator<'a, C>> {
        let mut converse = Box::new(converse);
        let conv = ffi::make_conversation(&mut *converse);
        let mut handle: *mut PamHandle = ptr::null_mut();

        match start(service, None, &conv, &mut handle) {
            PamReturnCode::SUCCESS => unsafe {
                Ok(Authenticator {
                    close_on_drop: true,
                    handler: C::Handler::create(converse, handle.as_mut().unwrap()),
                    is_authenticated: false,
                    has_open_session: false,
                    last_code: PamReturnCode::SUCCESS,
                })
            },
            code => Err(PamError(code)),
        }
    }

    pub fn environment(&mut self) -> Option<PamEnvList> {
        get_pam_env(self.handle_mut())
    }

    /// Mutable access to the conversation handler of this Authenticator
    pub fn handler_mut(&mut self) -> &mut C::Handler {
        &mut self.handler
    }

    /// Immutable access to the conversation handler of this Authenticator
    pub fn handler(&self) -> &C::Handler {
        &self.handler
    }

    /// Perform the authentication with the provided credentials
    pub fn authenticate(&mut self) -> PamResult<()> {
        self.last_code = authenticate(self.handle_mut(), PamFlag::NONE);
        if self.last_code != PamReturnCode::SUCCESS {
            // No need to reset here
            return Err(From::from(self.last_code));
        }

        self.is_authenticated = true;

        self.last_code = acct_mgmt(self.handle_mut(), PamFlag::NONE);
        if self.last_code != PamReturnCode::SUCCESS {
            // Probably not strictly neccessary but better be sure
            return self.reset();
        }
        Ok(())
    }

    /// Open a session for a previously authenticated user and
    /// initialize the environment appropriately (in PAM and regular enviroment variables).
    pub fn open_session(&mut self) -> PamResult<()> {
        if !self.is_authenticated {
            //TODO: is this the right return code?
            return Err(PamReturnCode::PERM_DENIED.into());
        }

        self.last_code = setcred(self.handle_mut(), PamFlag::ESTABLISH_CRED);
        if self.last_code != PamReturnCode::SUCCESS {
            return self.reset();
        }

        self.last_code = open_session(self.handle_mut(), PamFlag::NONE);
        if self.last_code != PamReturnCode::SUCCESS {
            return self.reset();
        }

        // Follow openSSH and call pam_setcred before and after open_session
        self.last_code = setcred(self.handle_mut(), PamFlag::REINITIALIZE_CRED);
        if self.last_code != PamReturnCode::SUCCESS {
            return self.reset();
        }

        self.has_open_session = true;
        Ok(())
    }

    pub fn env<T: AsRef<str>, U: AsRef<str>>(&mut self, name: T, value: U) -> PamResult<()> {
        let code = putenv(
            self.handle_mut(),
            &format!("{}={}", name.as_ref(), value.as_ref()),
        );

        if code != PamReturnCode::SUCCESS {
            Err(From::from(code))
        } else {
            Ok(())
        }
    }

    fn handle(&self) -> &PamHandle {
        C::Handler::handle(&self.handler)
    }

    fn handle_mut(&mut self) -> &mut PamHandle {
        C::Handler::handle_mut(&mut self.handler)
    }

    // Utility function to reset the pam handle in case of intermediate errors
    fn reset(&mut self) -> PamResult<()> {
        setcred(self.handle_mut(), PamFlag::DELETE_CRED);
        self.is_authenticated = false;
        Err(From::from(self.last_code))
    }
}

impl<'a, C: Converse<'a>> Drop for Authenticator<'a, C> {
    fn drop(&mut self) {
        if self.has_open_session && self.close_on_drop {
            close_session(self.handle_mut(), PamFlag::NONE);
        }
        let code = setcred(self.handle_mut(), PamFlag::DELETE_CRED);
        end(self.handle_mut(), code);
    }
}
