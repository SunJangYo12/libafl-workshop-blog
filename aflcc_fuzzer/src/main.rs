use std::{
    path::PathBuf,
};

use libafl_bolts::{
    tuples::{
        tuple_list,
    },
    current_nanos,
    rands::StdRand,
    AsMutSlice,
    shmem::{
        ShMem,
        ShMemProvider,
        UnixShMemProvider,
    },
};

use libafl::{
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
        MaxMapFeedback,
    },
    inputs::{
        BytesInput,
    },
    executors::{
        forkserver::ForkserverExecutor,
    },
    monitors::SimpleMonitor,
    mutators::{
        scheduled::{
            StdScheduledMutator,
            havoc_mutations,
        },
    },
    stages::mutational::StdMutationalStage,
    state::{
        StdState,
    },
    events::simple::SimpleEventManager,
    schedulers::QueueScheduler,
    observers::{
        HitcountsMapObserver,
        StdMapObserver,
    },
};


fn main() {
    const MAP_SIZE: usize = 65536;

    env_logger::init();

    /*
    * Note:
    * menggunakan instrumentasi dari AFL++ sebagai feedback
    */

    
    // Kali ini kita akan mendapat umpan balik berdasarkan yang dikompilasi dalam instrumentasi 
    // kita membutuhkan maxmapfeedback, yang dibaca dari peta dari hitcountsmapobserver 
    // ini akan menggunakan memori bersama dalam proses target untuk mengakses peta
    
    // first allocate shared memory
    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // Tulis ID ke env var untuk forkserver
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let shmembuf = shmem.as_mut_slice();

    // buat observer berdasarkan buffer yang dibagikan dengan target
    // menggunakan HitcountsMapObserver untuk membaca coverage map dari shared memory.
    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmembuf))
    };

    // Gunakan observer coverage untuk umpan balik berdasarkan mendapatkan cakupan maksimum
    // Menggunakan MaxMapFeedback untuk mendeteksi jalur eksekusi baru.
    let mut feedback = MaxMapFeedback::tracking(&edges_observer, true, false);


    // win on an crash
    let mut objective = CrashFeedback::new();

    let monitor = SimpleMonitor::new( |s| println!("{s}") );
    let mut mgr = SimpleEventManager::new(monitor);

    
    // kali ini kita dapat menggunakan executor forkserver, yang menggunakan instrumen di server fork 
    // mendapatkan jumlah eksekutif yang lebih besar per detik dengan tidak harus memulai proses untuk setiap menjalankan
    // artinya target binary hanya di-fork sekali, lalu setiap testcase dijalankan lewat proses child - jauh lebih cepat
    let mut executor = ForkserverExecutor::builder()
        .program("../fuzz_target/target_instrumented")
        .shmem_provider(&mut shmem_provider)
        .coverage_map_size(MAP_SIZE)
        .build(tuple_list!(edges_observer))
        .unwrap();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(PathBuf::from("./solutions")).unwrap(),
        &mut feedback,
        &mut objective,
    ).unwrap();

    // Di sini kita bisa bergabung di tokens_mutations(), karena afl-cc dapat mengatur autodict
    let mutator = StdScheduledMutator::with_max_stack_pow(
        havoc_mutations(),
        9,
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);



    // Muat korpus awal di bagian state 
    // kami dapat membiarkannya mengumpulkan umpan balik tentang input apa yang berguna atau tidak sekarang
    state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from("../fuzz_target/corpus/")]).unwrap();

    // fuzz
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).expect("Error in fuzz loop");

}
