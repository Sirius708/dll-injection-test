## Dll Injector Test

This is just a little dll injection test on windows I made mostly for myself.

I do not indent to alter the code structure itself, but if you find any problems with my code, 
like with the windows api calls, or have suggestions for the documentation I provided, 
feel free to inform me or open an issue.

You can do whatever you want with the source code, 
but I do not take any responsibility for any problems that arise from your use.

If you run into any problems running this code you can ask me, but firstly don't expect any response, 
and secondly it is likely that I am unable to help, as I myself am not super versed in the Win32 API and it's many ~~bugs~~ "features".

### Running this example

If you already have rust installed you're pretty much good to go, 
otherwise I greatly recommend you to install rustup as the rust toolchain of choice.

As this example is only intended for windows I will only provide install instructions for it.
If you try to run this for example on linux with wine or something similar, good luck.

#### Install rust on windows

1. Download [rustup-init.exe](https://rustup.rs/) from the official website.
2. Run rustup-init.exe
3. ?
4. Profit

Congratulations you now have rust installed on your system.

It should already have installed the default toolchain stable-msvc for windows.

If you intend to debug this example, you have to install the gnu toolchain, 
as debugging rust is currently not supported for msvc, at least at the time of writing this and to my knowledge.

To do that just run this command in your terminal and command prompt of choice:

`rustup toolchain add stable-gnu`

and 

`rustup default stable-gnu`

if you want that toolchain to be your default.

#### Using the command line

First you have to build the dll hook library before running the injector.

To do this just run this inside the project directory:

`cargo build`

This command will not just compile the dll hook but will also compile the injector exe with debug information.

To run the injector run this inside the project directory:

`target\debug\dll-injection-test.exe`

#### Using an IDE

1. Make sure that the whole project and all binaries get build before running the executable.
2. Set the working directory to `target\debug` or `target\release` depending on your build and run options (`--release` or not), 
or make sure that the hook dll is in the project root directory before running the injector.
3. Run the executable
4. Profit
