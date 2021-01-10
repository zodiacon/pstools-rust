use winplat::process::{self, ProcessInfoEx };
use winplat::core;
use std::collections::HashMap;
use clap::{Arg, App};
use num_format::{Locale, ToFormattedString};

fn main() -> Result<(), core::Win32Error> {
    let matches = App::new("pslist (Rust version)").version("0.1").author("Pavel Yosifovich").about("List process information")
        .arg(Arg::with_name("tree")
            .short("t").long("tree").help("Show process tree"))
        .arg(Arg::with_name("memory")
            .short("m").long("mem").help("Show memory information"))
        .arg(Arg::with_name("processid")
            .short("p").long("pid").help("Show specific process information")
            .value_name("PID").takes_value(true))
        .arg(Arg::with_name("processname")
            .short("n").long("pname").help("Show specific process(es) information by name")
            .value_name("NAME").takes_value(true))
        .get_matches();

    if matches.is_present("tree") {
        display_tree()?;
        return Ok(());
    }

    if let Some(pid) = matches.value_of("processid") {
        display_process( 
            match pid.trim().parse::<u32>() {
                Ok(pid) => pid,
                Err(e) => {
                    println!("{}", e);
                    return Ok(());
                }
            });
        return Ok(());
    }

    if let Some(pname) = matches.value_of("processname") {
        return display_processes(pname, matches.is_present("threadinfo"));
    }

    let processes = process::enum_processes_native(false)?;
    display_default(&processes);

    Ok(())
}

fn display_processes(pname: &str, include_threads: bool) -> Result<(), core::Win32Error> {
    todo!();
}

fn display_process(pid: u32) {
    if let Some(pi) = process::enum_processes_native_pid(pid, false) {
        // display process info
        display_process_info(&pi);
    }
    else {
        println!("Process ID {} not found", pid);
    }
}

fn display_default(processes: &Vec<ProcessInfoEx>) {
    println!("{:6} {:3} {:5} {:6} {:6} {:3} {:>10} {:>10} Name", "  PID", "SID", " Thr", " PPID", "  Han", "Pri", "Commit(K)", "WS(K)");

    for pi in processes.iter() {
        println!("{:6} {:3} {:5} {:6} {:6} {:3} {:>10} {:>10} {}", 
            pi.id, pi.session_id, pi.thread_count, pi.parent_id, pi.handle_count, pi.priority, 
            (pi.commit_size >> 10).to_formatted_string(&Locale::en), 
            (pi.working_set >> 10).to_formatted_string(&Locale::en),
            pi.name);
    }
}

fn display_tree() -> Result<(), core::Win32Error> {
    let processes = process::enum_processes_native(false)?;
    // build process tree
    let mut tree = Vec::with_capacity(32);
    let mut map = HashMap::with_capacity(256);

    for p in &processes {
        map.insert(p.id, p);
    }
    let map2 = map.clone();

    for p in &processes {
        let contains = map2.contains_key(&p.parent_id);
        if p.parent_id == 0 || !contains || map2[&p.parent_id].create_time > p.create_time {
            tree.push((p, 0));
            map.remove(&p.id);
            if p.id == 0 {
                continue;
            }
            let children = find_children(&map, &processes, &p, 1);
            children.iter().for_each(|p| {
                map.remove(&p.0);
                tree.push((&map2[&p.0], p.1));
            });
        }
    }
    for (p, indent) in tree.iter() {
        println!("{} {} ({})", String::from(" ").repeat(*indent as usize * 2), p.name, p.id);
    }
    Ok(())
}

fn find_children(map: &HashMap<u32, &ProcessInfoEx>, processes: &Vec<ProcessInfoEx>, parent: &ProcessInfoEx, indent: u32) -> Vec<(u32, u32)> {
    let mut children = Vec::new();
    for p in processes.iter() {
        if p.parent_id == parent.id && parent.create_time < p.create_time {
            children.push((p.id, indent));
            let mut children2 = find_children(&map, &processes, &p, indent + 1);
            children.append(&mut children2);
        }
    }
    children
}

fn display_process_info(pi: &ProcessInfoEx) {

}
