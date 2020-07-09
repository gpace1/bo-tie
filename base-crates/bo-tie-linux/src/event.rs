use bo_tie::hci::{
    events,
    EventMatcher,
};
use crate::WakerToken;
use std::collections::BTreeMap;
use std::convert::From;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Weak, Mutex};

#[derive(Clone)]
struct DynEventMatcher {
    weak_matcher: Weak<dyn EventMatcher>,
}

impl fmt::Debug for DynEventMatcher {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "DynEventMatcher")
    }
}

impl Eq for DynEventMatcher {}

impl std::cmp::PartialEq for DynEventMatcher {
    fn eq(&self, other: &DynEventMatcher) -> bool {
        self.weak_matcher.ptr_eq(&other.weak_matcher)
    }
}

#[derive(Debug)]
struct ExpEventInfo {
    /// The data returned when the corresponding event is received
    ///
    /// Will also contain the error is any error occurs
    data: Option<Result<events::EventsData, crate::Error>>,
    /// Waker token used for waking the thread when an event comes
    waker_token: WakerToken,
}

/// Expected event manager
#[derive(Debug)]
pub struct EventExpecter {
    expected: BTreeMap<Option<events::Events>, Vec<(DynEventMatcher, ExpEventInfo)>>,
}

impl EventExpecter {

    fn remove_expected_event(
        &mut self,
        event: Option<events::Events>,
        pattern: &DynEventMatcher)
    -> Option<ExpEventInfo>
    {
        if let Some(matchers) = self.expected.get_mut(&event) {

            let retval = matchers.iter()
                .enumerate()
                .find(|(_,(m,_))| m == pattern)
                .map(|(idx,_)| idx)
                .map(|idx| matchers.swap_remove(idx).1 );

            if matchers.len() == 0 {
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
        let inner_arc = unsafe { Pin::into_inner_unchecked(matcher) } as Arc<dyn EventMatcher>;

        let pat_key = DynEventMatcher { weak_matcher: Arc::downgrade(&inner_arc) };

        let mut gaurd = mutex.lock().expect("Couldn't acquire lock");

        match gaurd.expected.get_mut(&event)
            .and_then(|vec| vec.iter_mut().find(|(mat,_)| mat == &pat_key) )
        {
            None => {
                log::info!("Setting up expectation for event {:?}", event);

                let waker_token = WakerToken::from(waker.clone());

                let val = ExpEventInfo {
                    data: None,
                    waker_token,
                };

                let entry = gaurd.expected.entry(event).or_insert(Vec::new());

                entry.push((pat_key, val));

                // Remove any orphaned `DynEventMatcher` with the entry.
                //
                // A DynEventMatcher becomes orphaned when there are no more strong references to
                // the internal matcher. This generally happens when the original caller containing
                // the matcher supplied to expect_event doesn't exist anymore.
                //
                // Just to keep this function snappy, this is done only for the current event entry.

                let mut cnt = 0;

                while cnt < entry.len() {

                    if entry[cnt].0.weak_matcher.upgrade().is_none() {
                        entry.swap_remove(cnt);
                    }

                    cnt += 1;
                }

                None
            }
            Some((_,ref mut val)) => {

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

                let process_expected = |patterns_map: &mut Vec<(DynEventMatcher, ExpEventInfo)>| {

                    for (dyn_matcher, ref mut exp_event_info) in patterns_map.iter_mut() {
                        if dyn_matcher.weak_matcher.upgrade()
                            .map(|m| m.match_event(&event_data))
                            .unwrap_or(false)
                        {
                            log::debug!("Matched event {:?}", received_event);

                            exp_event_info.data = Some(Ok(event_data));
                            exp_event_info.waker_token.trigger();

                            break;
                        }
                    }
                };

                let expected = &mut self.expected_events.lock().unwrap().expected;

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
