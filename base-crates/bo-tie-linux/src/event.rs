use bo_tie::hci::{
    events,
    EventMatcher,
};
use crate::WakerToken;
use crate::timeout;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::convert::From;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

struct TimeoutCallback {
    todo: Box<dyn Fn() + Send + Sync>
}

impl fmt::Debug for TimeoutCallback {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TimeoutCallback")
    }
}

impl timeout::OnTimeout for TimeoutCallback {
    fn on_timeout(&self) {
        (self.todo)()
    }
}

#[derive(Clone)]
struct DynEventMatcher {
    matcher: Pin<Arc<dyn EventMatcher>>,
}

impl fmt::Debug for DynEventMatcher {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "DynEventMatcher")
    }
}

impl Eq for DynEventMatcher {}

impl Ord for DynEventMatcher {
    fn cmp(&self, other: &Self) -> Ordering {
        (&*self.matcher as *const dyn EventMatcher).cmp(&(&*other.matcher as *const dyn EventMatcher))
    }
}

impl std::cmp::PartialEq for DynEventMatcher {
    fn eq(&self, other: &DynEventMatcher) -> bool {
        (&*self.matcher as *const dyn EventMatcher) == (&*other.matcher as *const dyn EventMatcher)
    }
}

impl std::cmp::PartialOrd for DynEventMatcher {
    fn partial_cmp(&self, other: &DynEventMatcher) -> Option<std::cmp::Ordering> {
        (&*self.matcher as *const dyn EventMatcher).partial_cmp(&(&*other.matcher as *const dyn EventMatcher))
    }
}

#[derive(Debug)]
struct ExpEventInfo {
    /// The data returned when the coresponding event is received
    ///
    /// Will also contain the error is any error occurs
    data: Option<Result<events::EventsData, crate::Error>>,
    /// Waker token used for waking the thread when an event comes
    waker_token: WakerToken,
    /// Timer used to shortcircuit
    stop_timer: Option<timeout::StopTimeout>,
}

/// Expected event manager
#[derive(Debug)]
pub struct EventExpecter {
    expected: BTreeMap<events::Events, BTreeMap<DynEventMatcher, ExpEventInfo>>,
}

impl EventExpecter {

    fn get_stop_timer(
        self: &mut std::sync::MutexGuard<Self>,
        mut timeout_builder: timeout::TimeoutBuilder,
        callback: Box<dyn Fn() + Send + Sync>)
    -> Result<timeout::StopTimeout, crate::Error>
    {
        timeout_builder.set_timeout_callback( Box::new(TimeoutCallback { todo: callback }) );

        let stop_timer = match timeout_builder.make_stop_timer() {
            Ok(val) => val,
            Err(e) => return Err(e),
        };

        if let Err(e) = timeout_builder.enable_timer() {
            return Err(e)
        }

        Ok(stop_timer)
    }

    fn remove_expected_event(
        self: &mut std::sync::MutexGuard<Self>,
        event: events::Events,
        pattern: &DynEventMatcher)
    -> Option<ExpEventInfo>
    {
        if let Some(map) = self.expected.get_mut(&event) {

            let retval = map.remove(&pattern);

            if map.len() == 0 {
                self.expected.remove(&event);
            }

            retval
        } else {
            None
        }
    }

    pub fn expect_event<P>(
        mutex: Arc<Mutex<Self>>,
        event: events::Events,
        waker: &core::task::Waker,
        matcher: Pin<Arc<P>>,
        timeout_builder: Option<timeout::TimeoutBuilder>)
        -> Option<Result<events::EventsData, crate::Error>>
        where P: bo_tie::hci::EventMatcher + 'static
    {
        let pat_key = DynEventMatcher { matcher };

        let mut gaurd = mutex.lock().expect("Couldn't acquire lock");

        match gaurd.expected.get(&event).and_then(|map| map.get(&pat_key) )
        {
            None => {
                log::debug!("Setting up expectation for event {:?}", event);

                let waker_token = WakerToken::from(waker.clone());

                let mutex_clone = mutex.clone();
                let event_clone = event.clone();
                let pat_key_clone = pat_key.clone();

                let callback = move || {
                    let mut gaurd = mutex_clone.lock().expect("Couldn't unlock");

                    if let Some(info) = gaurd.expected.get_mut(&event_clone)
                        .and_then(|map| map.get_mut(&pat_key_clone) )
                    {
                        info.data = Some(Err(crate::Error::Timeout));

                        info.stop_timer = None;

                        info.waker_token.trigger();
                    }
                };

                let stop_timer = match timeout_builder {
                    Some(tb) => {
                        match gaurd.get_stop_timer( tb, Box::new( callback ) ) {
                            Ok(ti) => Some(ti),
                            Err(e) => return Some(Err(e))
                        }
                    },
                    None => None,
                };

                let val = ExpEventInfo {
                    data: None,
                    waker_token: waker_token,
                    stop_timer: stop_timer,
                };

                gaurd.expected.entry(event).or_insert(BTreeMap::new()).insert(pat_key, val);

                None
            }
            Some(ref val) => {

                if val.waker_token.triggered() {
                    log::debug!("Retrieving data for event {:?}", event);

                    let expected = gaurd.remove_expected_event(event, &pat_key).unwrap();

                    if let Some(stop_timer) = expected.stop_timer {
                         if let Err(err) = stop_timer.stop() {
                             return Some(Err(err));
                         }
                    }

                    expected.data

                } else {
                    None
                }
            }
        }
    }
}

pub struct EventProcessor {
    expected_events: Arc<Mutex<EventExpecter>>,
}

impl EventProcessor {

    /// Processor for events from a bluetooth controller
    pub fn process(&mut self, raw_event_packet: &[u8]) {

        match events::EventsData::from_packet(raw_event_packet) {
            Ok(event_data) => {
                let received_event = event_data.get_enum_name();

                if let Some(ref mut patterns_map) = self.expected_events.lock()
                    .expect("Couldn't acquire mutex")
                    .expected.get_mut(&received_event)
                {
                    for (dyn_matcher, ref mut exp_event_info) in patterns_map.iter_mut() {
                        if dyn_matcher.matcher.match_event(&event_data) {

                            log::debug!("Matched event {:?}", received_event);

                            exp_event_info.data = Some(Ok(event_data));
                            exp_event_info.waker_token.trigger();

                            break;
                        }
                    }

                    // Any events not matched are ignored
                }
            },
            Err(e) => log::error!("HCI Event Error: {}", e),
        }
    }
}

pub struct EventSetup;

impl EventSetup {

    pub fn setup() -> (Arc<Mutex<EventExpecter>>, EventProcessor) {

        let expecter = Arc::new(Mutex::new(EventExpecter {
            expected: BTreeMap::new(),
        }));

        let processor = EventProcessor {
            expected_events: expecter.clone(),
        };

        (expecter, processor)
    }
}
