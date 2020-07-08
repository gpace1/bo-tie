use bo_tie::hci::{
    events,
    EventMatcher,
};
use crate::WakerToken;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::convert::From;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

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
}

/// Expected event manager
#[derive(Debug)]
pub struct EventExpecter {
    expected: BTreeMap<Option<events::Events>, BTreeMap<DynEventMatcher, ExpEventInfo>>,
}

impl EventExpecter {

    fn remove_expected_event(
        &mut self,
        event: Option<events::Events>,
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
        event: Option<events::Events>,
        waker: &core::task::Waker,
        matcher: Pin<Arc<P>>,
    ) -> Option<Result<events::EventsData, crate::Error>>
    where P: bo_tie::hci::EventMatcher + 'static
    {
        let pat_key = DynEventMatcher { matcher };

        let mut gaurd = mutex.lock().expect("Couldn't acquire lock");

        match gaurd.expected.get_mut(&event).and_then(|map| map.get_mut(&pat_key) )
        {
            None => {
                log::info!("Setting up expectation for event {:?}", event);

                let waker_token = WakerToken::from(waker.clone());

                let val = ExpEventInfo {
                    data: None,
                    waker_token,
                };

                gaurd.expected.entry(event).or_insert(BTreeMap::new()).insert(pat_key, val);

                None
            }
            Some(ref mut val) => {

                if val.waker_token.triggered() {
                    log::debug!("Retrieving data for event {:?}", event);

                    let expected = gaurd.remove_expected_event(event, &pat_key).unwrap();

                    expected.data

                } else {

                    if val.waker_token.change_waker(waker) {
                        log::info!("Waker updated for new context")
                    }

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
                let received_event = event_data.get_event_name();

                let process_expected = |patterns_map: &mut BTreeMap<DynEventMatcher, ExpEventInfo>| {
                    for (dyn_matcher, ref mut exp_event_info) in patterns_map.iter_mut() {
                        if dyn_matcher.matcher.match_event(&event_data) {

                            log::debug!("Matched event {:?}", received_event);

                            exp_event_info.data = Some(Ok(event_data));
                            exp_event_info.waker_token.trigger();

                            break;
                        }
                    }
                };

                let expected = &mut self.expected_events.lock().expect("Couldn't acquire mutex").expected;

                if let Some(ref mut patterns_map) = expected.get_mut(&Some(received_event)) {
                    process_expected(patterns_map)
                } else if let Some(ref mut patterns_map) = expected.get_mut(&None) {
                    process_expected(patterns_map)
                }

                // Any events not matched are ignored
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
