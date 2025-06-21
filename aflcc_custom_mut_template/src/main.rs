use std::{
    path::PathBuf,
};

use libafl_bolts::{
    Named,
    tuples::{
        tuple_list,
    },
    current_nanos,
    rands::StdRand,
    rands::Rand,
    AsMutSlice,
    shmem::{
        ShMem,
        ShMemProvider,
        UnixShMemProvider,
    },
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
        MaxMapFeedback,
    },
    inputs::{
        BytesInput,
        HasBytesVec,
    },
    executors::{
        forkserver::ForkserverExecutor,
    },
    monitors::SimpleMonitor,
    mutators::{
        scheduled::{
            StdScheduledMutator,
        },
        mutations::{
            BytesInsertMutator,
            BytesDeleteMutator,
        },
        MutationResult,
        Mutator,
    },
    stages::mutational::StdMutationalStage,
    state::{
        StdState,
        HasRand,
    },
    events::simple::SimpleEventManager,
    schedulers::QueueScheduler,
    observers::{
        HitcountsMapObserver,
        StdMapObserver,
    },
};

// Ini adalah struktur kami yang akan mengimplementasikan mutator 
// menambahkan anggota yang diperlukan di sini
struct AlphaByteSwapMutator {
}

impl<I, S> Mutator<I, S> for AlphaByteSwapMutator
where
    I: HasBytesVec,
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // Di sini kami menerapkan mutasi acak kami
        /*
            TODO

            Mengingat input, bermutasinya dengan cara yang cerdas untuk target kami

            Our input for this implements HasBytesVec
            so you can use input.bytes_mut() to get a mutable vector

            Input kami untuk ini mengimplementasikan HasBytesVec
            sehingga Anda dapat menggunakan input.bytes_mut()
            untuk mendapatkan vektor yang bisa berubah

            Lihat implementor mutate lainnya untuk contoh dalam repo
            https://docs.rs/libafl/latest/libafl/mutators/trait.Mutator.html#implementors

            Anda dapat menggunakan state.rand_mut() untuk mengakses sumber acak
            https://docs.rs/libafl_bolts/0.11.1/libafl_bolts/rands/trait.Rand.html

            return Ok(MutationResult::Mutated) Saat Anda bermutasi input
            or Ok(MutationResult::Skipped) Saat Anda tidak
        */

        Ok(MutationResult::Skipped)
    }
}

impl Named for AlphaByteSwapMutator {
    fn name(&self) -> &str {
        "AlphaByteSwapMutator"
    }
}

impl AlphaByteSwapMutator {
    fn new() -> Self {
        // Tambahkan inisialisasi mutator kami yang dibutuhkan di sini
        Self {
        }
    }
}

fn main() {
    const MAP_SIZE: usize = 65536;

    env_logger::init();

    // Ini akan sama dengan fuzzer aflcc 
    // kecuali kami akan menentukan mutator khusus

    // first allocate shared memory
    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // write the id to the env var for the forkserver
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let shmembuf = shmem.as_mut_slice();
    // build an observer based on that buffer shared with the target
    let edges_observer = unsafe {HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmembuf))};
    // use that observed coverage to feedback based on obtaining maximum coverage
    let mut feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

    // win on an crash
    let mut objective = CrashFeedback::new();

    let monitor = SimpleMonitor::new( |s| println!("{s}") );
    let mut mgr = SimpleEventManager::new(monitor);

    // use a forkserver
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

    // Kami akan menentukan mutator khusus kami, serta dua mutator bermanfaat lainnya untuk tumbuh atau menyusut
    let mutator = StdScheduledMutator::with_max_stack_pow(
        tuple_list!(
            AlphaByteSwapMutator::new(),
            BytesDeleteMutator::new(),
            BytesInsertMutator::new(),
        ),
        9,
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);


    // Muat korpus awal di state
    // kami dapat membiarkannya mengumpulkan umpan balik tentang
    // input apa yang berguna atau tidak sekarang
    state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from("../fuzz_target/corpus/")]).unwrap();

    // fuzz
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).expect("Error in fuzz loop");

}
