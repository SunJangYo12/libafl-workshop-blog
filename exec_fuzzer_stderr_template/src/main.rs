use std::{
    path::PathBuf,
    collections::{
        HashSet,
        hash_map::DefaultHasher,
    },
    hash::Hasher,
};


use libafl_bolts::{
    Named,
    tuples::{
        tuple_list,
    },
    current_nanos,
    rands::StdRand,
};

use libafl::{
    Error,
    corpus::{
        inmemory::InMemoryCorpus,
        ondisk::OnDiskCorpus,
    },
    fuzzer::{
        StdFuzzer,
        Fuzzer,
    },
    feedbacks::{
        CrashFeedback,
        Feedback,
    },
    inputs::{
        BytesInput,
        UsesInput,
    },
    observers::{
        stdio::StdErrObserver,
        ObserversTuple,
    },
    executors::{
        command::CommandExecutor,
        ExitKind,
    },
    //monitors::tui::TuiMonitor,
    monitors::SimpleMonitor,
    mutators::scheduled::{
        StdScheduledMutator,
        havoc_mutations,
    },
    stages::mutational::StdMutationalStage,
    state::{
        StdState,
        HasClientPerfMonitor,
    },
    events::{
        simple::SimpleEventManager,
        EventFirer,
    },
    schedulers::RandScheduler,
};


// Umpan balik khusus kami berdasarkan stdout
// Anda dapat menambahkan anggota di sini untuk status pelacakan yang akan digunakan dalam fungsi is_interesting Anda
#[derive(Clone, Debug)]
struct NewOutputFeedback {
    name: String,
    observer_name: String,
}

impl NewOutputFeedback {
    fn new(name: &str, observer_name: &str) -> Self {
        // return a new NewOutputFeedback
        // Pastikan untuk membuat instantiate item yang Anda tambahkan ke struct di sini
        Self {
            name: name.to_string(),
            observer_name: observer_name.to_string(),
        }
    }
}

impl<S> Feedback<S> for NewOutputFeedback
where
    S: UsesInput + HasClientPerfMonitor,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind
    ) -> Result<bool, Error>
       where EM: EventFirer<State = S>,
             OT: ObserversTuple<S>
    {
        // Di sini kami mengimplementasikan IS_Interesting
        // kami mengambil output dari Stderr dan melihat apakah itu tidak sebelum dilihat 
        // fuzzer kami akan mencatat input yang memberikan output baru pada stderr 
        // dan akan lebih lanjut mengulangi input ini
        let observer = observers.match_name::<StdErrObserver>(&self.observer_name)
            .expect("A NewOutputFeedback needs a StdErrObserver");

        /*
            TODO
            Menggunakan output dari StdErrObserver Tentukan apakah kita telah mengamati sesuatu yang baru lihat:
            https://docs.rs/libafl/latest/libafl/observers/stdio/struct.StdErrObserver.html

            Lihat implementasi lain dari umpan balik sifat untuk contoh:
            https://docs.rs/libafl/latest/libafl/feedbacks/trait.Feedback.html#implementors

            return Ok(false) for uninteresting inputs
            return Ok(true) for interesting inputs
        */
        
        Ok(false)

    }
}

impl Named for NewOutputFeedback {
    fn name(&self) -> &str {
        &self.name
    }
}

fn main() {
    env_logger::init();

    /* 
    * Tujuan:
    * kita pakai instrumentasi dari debuger (-g) dengan menangkap stder
    * untuk feedback
    */


    // Kami dapat menggunakan stdout yang disediakan oleh program untuk mengetahui kapan kami mencapai poin baru
    // kami menggunakan umpan balik khusus untuk ini, disediakan pengamatan oleh StdErrObserver
    let observer = StdErrObserver::new("stderr_ob".to_string());
    let mut feedback = NewOutputFeedback::new("stderr_feedback", observer.name());

    // Kemenangan masih akan menjadi kecelakaan yang bisa kita dapatkan
    let mut objective = CrashFeedback::new();

    // simple monitor and event manager to print out our progress
    let monitor = SimpleMonitor::new( |s| println!("{s}") );
    let mut mgr = SimpleEventManager::new(monitor);

    // Masih hanya menjalankan subproses 
    // kali ini menggunakan target build yang mencetak log ke stderr
    let mut executor = CommandExecutor::builder()
        .program("../fuzz_target/target_dbg")
        .build(tuple_list!(observer))
        .unwrap();

    // state kita
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(PathBuf::from("./solutions")).unwrap(),
        &mut feedback,
        &mut objective,
    ).unwrap();


    // keep our normal mutation stage
    let mutator = StdScheduledMutator::with_max_stack_pow(
        havoc_mutations(),
        9,                                                      // maximum mutation iterations
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // jadwalkan secara acak dari input kami
    let scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);


    // Muat korpus awal di bagian state kami 
    // kami memiliki umpan balik sekarang, jadi kami tidak perlu menggunakan _forced lagi 
    // selama umpan balik kami(feedback) dapat mengetahui input apa yang menarik
    state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from("../fuzz_target/corpus/")]).unwrap();

    // fuzz
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).expect("Error in fuzz loop");

}
