use std::{
    path::PathBuf,
};

use libafl_bolts::{
    tuples::{
        tuple_list,
    },
    current_nanos,
    rands::StdRand,
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
        ConstFeedback,
    },
    inputs::{
        BytesInput,
    },
    executors::{
        command::CommandExecutor,
    },
    monitors::SimpleMonitor,
    mutators::scheduled::{
        StdScheduledMutator,
        havoc_mutations,
    },
    stages::mutational::StdMutationalStage,
    state::{
        StdState,
    },
    events::simple::SimpleEventManager,
    schedulers::RandScheduler,
};

fn main() {
    /*
    * Tujuan:
    * hanya fuzzing binary dan fuzzer tidak pakai instrumentasi
    * hanya mendeteksi crash.
    */


    // ini mari kita lihat log internal libafl untuk info debugging yang lebih baik 
    // cukup gunakan rust_log = debug atau apapun
    env_logger::init();

    // Kami tidak memiliki instrumentasi di sini untuk memberi tahu kami ketika kami menemukan jalur baru 
    // jadi kami tidak punya umpan balik
    let mut feedback = ConstFeedback::False;

    // "objective" kami adalah umpan balik yang memberi tahu fuzzer kami ketika kami menang!     
    // kita bisa memasukkan batas waktu, output tertentu, file yang dibuat, dll 
    // di sini kita hanya akan menang ketika target kita macet
    let mut objective = CrashFeedback::new();

    // kita perlu membuat monitor kita 
    // Ini hanya untuk melaporkan statistik kembali ke layar kita 
    // libafl termasuk beberapa cara yang lebih bagus untuk menunjukkan ini juga, seperti tuimonitor
    let monitor = SimpleMonitor::new( |s| println!("{s}") );

    
    // event manager mengikuti acara/statistik selama fuzzer 
    // di sini kami dapat secara terprogram menanggapi acara tersebut 
    // tetapi kami hanya akan menggunakan manajer yang mengirimkan acara ke monitor
    let mut mgr = SimpleEventManager::new(monitor);


    // kita perlu membuat executor 
    // ini menentukan bagaimana kita menjalankan setiap test case 
    // ini bisa menggunakan qemu, frida, atau menggunakan forkserver yang dikompilasi 
    // kita hanya akan menggunakan "commandexecutor" yang paling sederhana yang menjalankan proses 
    // secara default itu akan menggunakan stdin untuk mengirim lebih dari input, kecuali jika kita spesifikasi sebaliknya 
    let mut executor = CommandExecutor::builder()
        .program("../fuzz_target/target")
        .build(tuple_list!())
        .unwrap();


    // Kami membutuhkan bagian state untuk memegang fuzzing state 
    // ia melacak corpus kami (input dan solusi) 
    // dan metadata lainnya
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(PathBuf::from("./solutions")).unwrap(),
        &mut feedback,
        &mut objective,
    ).unwrap();


    // kita perlu membuat tahapan kita
    // ini akan dieksekusi untuk setiap testcase baru yang dieksekusi
    // yang kita butuhkan hanyalah mutasi byte normal untuk saat ini 
    // tetapi di sini kita juga bisa memiliki tahapan penelusuran, 
    // kalibrasi, generasi, tahap sinkron, etc
    // Lihat implementasi sifat panggung di libafl
    let mutator = StdScheduledMutator::with_max_stack_pow(
        havoc_mutations(),
        9,                                                      // maximum mutation iterations
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // Kami membutuhkan scheduler/penjadwal untuk fuzzer kami untuk memilih cara menjadwalkan input di corpus kami
    let scheduler = RandScheduler::new();
    // Sekarang kita bisa membangun fuzzer kita
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);



    // Muat korpus awal di bagian state 
    // karena kami kekurangan umpan balik(feedback), kami harus memaksakan ini, 
    // jika tidak, ia hanya akan memuat input yang dianggap menarik 
    // yang akan menghasilkan korpus kosong untuk kami
    state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from("../fuzz_target/corpus/")]).unwrap();

    // fuzz
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).expect("Error in fuzz loop");

}
