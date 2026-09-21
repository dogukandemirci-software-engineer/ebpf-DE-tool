use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{Context, Result};
use aya::{include_bytes_aligned, programs::TracePoint, Ebpf};
use colored::Colorize;

const TRACE_PIPE: &str = "/sys/kernel/debug/tracing/trace_pipe";

fn main() -> Result<()> {
    let object = include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpfel-unknown-none/release/hello-ebpf"
    ));

    let mut ebpf = Ebpf::load(object).context("eBPF nesnesi yüklenemedi")?;

    print_banner();

    let program: &mut TracePoint = ebpf
        .program_mut("hello")
        .context("'hello' eBPF programı bulunamadı")?
        .try_into()?;

    program
        .load()
        .context("eBPF programı çekirdeğe yüklenemedi")?;
    program
        .attach("syscalls", "sys_enter_execve")
        .context("sys_enter_execve tracepoint'ine bağlanılamadı")?;

    let trace_pipe = trace_pipe_path();
    println!("Rust eBPF programı yüklendi.");
    println!("Başka bir terminalde örneğin `ls` çalıştırın (çıkış: Ctrl+C).\n");

    let file = File::open(trace_pipe)
        .with_context(|| format!("{trace_pipe} açılamadı; debugfs bağlı mı?"))?;

    for line in BufReader::new(file).lines() {
        let line = line.context("trace_pipe okunamadı")?;
        if line.contains(" calistirildi, pid=") {
            println!("{line}");
        }
    }

    Ok(())
}

fn trace_pipe_path() -> &'static str {
    if Path::new(TRACE_PIPE).exists() {
        TRACE_PIPE
    } else {
        "/sys/kernel/tracing/trace_pipe"
    }
}

fn print_banner() {
let banner: &str = r#"
                                :=**#-@:%%*+:                             
                      #%=+%%%##**+++=-=+***%%*-%#                      
                     +#%%==:-=-. .:::=-::::-*+@@%+                     
                @ +#@%*=:....... .-=+*#*+-:.:*+-*%@#= @%               
              %@@@@@=::...::---:-:..::.-==-:..:---=@@@@@%              
        .+*: =%@@@%:- :--=+=.::::---=+*%@#:..:-==--:@@@@#= .*+.        
         -*@%#@%@@:-:::.::-==:.  .:*#*++=++:.. .-=-=:@@%@##@#-         
        %%=%@@@%%=+:..:.......:-+##*+#%%#+::..:-*=:.++%%%@@%+%%        
      %@@@@@%@@*-=.  ..::=--:==:-:-:---##%*-:..:::.:.=.@@@%@@@@@%      
       %#@@%@#==--. .:-:.:=@@#%@@@@@@*=-:....--=+---#-: #@@%@@##       
      %#@@#%#--=-:.:.-#@%@@@@@@@@@@@@@@@@@@%#+:..:.:=:*. %%%#@@*%#     
    %@@@@@#---=:--:--=@@@@@@@@@@@@@@@@@@@@@@+@@@#===:=-:    @@@@@@%    
  @@@@@@%=+*=.. :.-%=%+-=%@@@@##@@@@@@%#%@@@@@+:=#==-=+-      @@@@@@@  
    *#@%+-....-: .%%-*:   .=%@@@@@=@-@@@@@#-.   :*-*+-+.@@@@@@@@@#*    
    :-==-=.:=-:...#*-@=.     .:-+-#@%-+-:.  .   =@=+%.+.    @%@@@@=    
   -:.:::---=-..: ::#@*.    . .:-#=@-%-:  .    :*@#:-+:      @@#@@%    
   ++=%#%*.==:..:.*#@@@#::--*@@@@-.: -%@@%%--=.=@@@%#-   @@@@%@#@@=    
  ..=@%##@-=...-. *#@@@@*=-+.*%#=  @  =#%*.=-=%@@@@@*:       @%#%@+:.  
 ::+@@@@#+==--.:...=*@@@*::#=%@@+..@.:=@@%-#:-*@@@#-:=- @@@@@@@@@@@+:: 
    %@%=:#%#-::=-.-..:.. .=:*@@%%@@*@@@%@@*:-  ..=:.+*.  @@@@% +%@*    
    @@%+*.::-+.+-.-+.:--:..##*+**=+@*-==-=*%..:--:--:@: @@@%#@@#%@%    
    #-#:%=*:-#=**=-= -+:: @@@@@@@@.@@@@@@@@ ..+- #**=  @@%*%@#@%#     
    +@@%%=+:-+- .#+@ .@@+. .=*. .. ...:+-.  *%@..-:. *%@@@* #=@@+     
   -=%@@#++.:++ ::%%..@@#+:*. :#%+.=@@=  .=.=@@..*#-  @@%%@@@@@#==-    
     =@#+=*:+*+  ==-.:%@@#+@%:=#@@%.@@@%**=@@%@:-=#= @@@+ #@##@-      
    %@@@@==::=@@ :=*-.+@@@%+#@#%@@@#-@@%*-+@@@+:+%=. @@#@%@+@@@@%     
      @*%@==+:**@-==*. .:#@%+#=:#@@@@#@@+=@@-: .=+==@*+ +@%@%=@      
        %*#=-: *@@:+#+@@ .#@%@%-#@@@@+@@*%@: @@+#+:#@  #@@@##         
        =#@=*@%*@@@+**%## .-#@%%+@@@@%@@@#- %%%*++@@@*#@@%@%+         
        :#= -+*@@@#@@-#@%* @.=@@@::@@@*@@@+#  %@#-@@#%@@#+  =#:        
        .   ::.@%#@@***@@%%%%-+#+-=@@%*@@@*#%#@@***@@#%@      .        
             .     %@@@@*#@@%%@%--@@@%@@%##@@#*@@@@#                   
                   %% -@*%@@##+=-%@@@%@@#=*@@%+@- %%                   
                      -@# @%@@@+#@@@#@@%=%@%# *@:                      
                       ++    @%#@@@@@@@+*##   ++                       
                             @#*#@@@@@%#.+=                            
                               -=#@@#@@+#%=                            
                                :-*#@@@#+=:                            
                                  .==-==-.  
                          AUTHOR: @dogukan-demirci
                               VERSION: 0.1.0
                             -=DETECT THE TOMB=-
    "#;

    let banner_colored = banner.red().bold();

    print!("{banner_colored}");
}

