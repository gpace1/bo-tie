use crate::{
    ArcFileDesc,
    EPollResult,
    Error,
};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::collections::HashMap;

fn remove_timer_from_epoll( epoll_fd: ArcFileDesc, timer_fd: ArcFileDesc) -> Result<(), Error> {
    use nix::sys::epoll;

    epoll::epoll_ctl(
        epoll_fd.raw_fd(),
        epoll::EpollOp::EpollCtlDel,
        timer_fd.raw_fd(),
        None
    )
    .map_err(|e| Error::from(e))?;

    Ok(())
}

#[derive(Debug)]
pub struct Timeout {
    epoll_fd: ArcFileDesc,
    timer_fd: ArcFileDesc,
    callback: Box<dyn OnTimeout>,
}

impl Timeout {

    pub fn remove_timer(&self) -> Result<(), Error>{
        remove_timer_from_epoll(self.epoll_fd.clone(), self.timer_fd.clone())
    }

    /// Triggers the callback and removes the timer
    pub fn trigger(self) -> Result<(), Error> {
        self.remove_timer()?;

        self.callback.on_timeout();

        Ok(())
    }
}

#[derive(Debug)]
pub struct StopTimeout {
    epoll_fd: ArcFileDesc,
    timer_fd: ArcFileDesc,
    id: u64,
    timeout_manager: Arc<Mutex<TimeoutManager>>,
}

impl StopTimeout {
    pub fn stop(self) -> Result<(), Error> {
        lock!(self.timeout_manager)
        .remove(self.id)
        .or(Err(Error::Other("Timeout ID doesn't exist".to_string())))?;

        remove_timer_from_epoll(self.epoll_fd, self.timer_fd)
    }
}

pub trait OnTimeout: Send + fmt::Debug {
    fn on_timeout(&self);
}

pub struct TimeoutBuilder {
    epoll_fd: ArcFileDesc,
    timer_fd: ArcFileDesc,
    callback: Option<Box<dyn OnTimeout>>,
    timeout_manager: Arc<Mutex<TimeoutManager>>,
    time: Duration,
    id: u64,
}

impl TimeoutBuilder {

    pub fn new( epoll_fd: ArcFileDesc, time: Duration, tm: Arc<Mutex<TimeoutManager>>) -> Result<TimeoutBuilder, Error>
    {
        use nix::libc;
        use nix::errno::Errno;
        use nix::sys::epoll;

        let timer_fd = unsafe{ libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) };

        if timer_fd < 0 { return Err(Error::from(Errno::last())); }

        let timer_id = EPollResult::make_timeout_id(timer_fd);

        epoll::epoll_ctl(
            epoll_fd.raw_fd(),
            epoll::EpollOp::EpollCtlAdd,
            timer_fd,
            &mut epoll::EpollEvent::new(epoll::EpollFlags::EPOLLIN, timer_id)
        )
        .map_err(|e| Error::from(e))?;

        Ok(TimeoutBuilder {
            epoll_fd: epoll_fd,
            timer_fd: ArcFileDesc::from(timer_fd),
            callback: None,
            timeout_manager: tm,
            time: time,
            id: timer_id,
        })
    }

    /// Must be called to set the function that is called when a timeout occurs.
    pub fn set_timeout_callback(&mut self, callback: Box<dyn OnTimeout>) {
        self.callback = Some(callback);
    }

    /// set_timeout_callback must be called before this is called to set the callback method
    /// because a callback is needed to construct a "dummy" timeout object
    pub fn make_stop_timer(&self) -> Result<StopTimeout, Error> {
        Ok(StopTimeout {
            epoll_fd: self.epoll_fd.clone(),
            timer_fd: self.timer_fd.clone(),
            id: self.id.clone(),
            timeout_manager: self.timeout_manager.clone(),
        })
    }

    /// set_timeout_callback must be called to set the timeout callback or this will just return
    /// an error
    pub fn enable_timer(mut self) -> Result<(), Error>
    {
        use nix::errno::Errno;
        use nix::libc;
        use std::ptr::null_mut;

        let timeout = Timeout {
            epoll_fd: self.epoll_fd.clone(),
            timer_fd: self.timer_fd.clone(),
            callback: self.callback.take().ok_or(Error::Other("timeout callback not set".into()))?,
        };

        let timeout_spec = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: self.time.as_secs() as libc::time_t,
                tv_nsec: self.time.subsec_nanos() as libc::c_long,
            }
        };

        lock!(self.timeout_manager).add(self.id, timeout)?;

        if 0 > unsafe{ libc::timerfd_settime(
            self.timer_fd.raw_fd(),
            0,
            &timeout_spec as *const libc::itimerspec,
            null_mut()) }
        {
            lock!(self.timeout_manager).remove(self.id)?;
            return Err(Error::from(Errno::last()));
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct TimeoutManager {
    timeouts: HashMap<u64,Timeout>
}

impl TimeoutManager {
    pub fn new() -> Self {
        TimeoutManager {
            timeouts: HashMap::new()
        }
    }

    pub fn add(&mut self, timeout_id: u64, timeout: Timeout ) -> Result<(), Error> {
        match self.timeouts.insert(timeout_id, timeout) {
            None => Ok(()),
            Some(v) => {
                self.timeouts.insert(timeout_id, v);
                Err(Error::Other("Timeout ID already exists".to_string()))
            }
        }
    }

    pub fn remove(&mut self, timeout_id: u64) -> Result<Timeout, Error> {
        self.timeouts.remove(&timeout_id).ok_or(Error::Other("Timeout ID doesn't exist".to_string()))
    }
}
