## Discription of main class  

### project   

  #### &nbsp;&nbsp;new project
  ```python
  b = angr.Project('/bin/true')
  b.arch #architecture
  b.entry #entry address
  b.filname
  b.loader #load address
  ```
  #### &nbsp;&nbsp;loader
  ```python
  b.loader.shared_objects #this is a dictionary of the objects that are loaded as part of loading the binary
  b.loader.memory[b.loader.min_addr()] #this is the memory space of the process after being loaded.
  b.loader.main_bin #this is the object for the main binary
  b.loader.addr_belongs_to_object(b.loader.max_addr()) #this retrieves the binary object which maps memory at the specified address
  b.loader.find_symbol_got_entry('__libc_start_main') #Get the address of the GOT slot for a symbol (in the main binary)
  b.loader.main_bin.deps #this is a list of the names of libraries the program depend on.
  b.loader.main_bin.memory #this is a dict of the memory contents of *just* the main binary
  b.loader.shared_objects['libc.so.6'].imports #this is a dict (name->ELFRelocation) of imports required by the libc which was loaded
  ```
### analyses  
  #### &nbsp;&nbsp; Analysis the binary and get CFG, DFG, VFG, Slice, and so on.
  ```python
  b = angr.Project('/bin/true')
  cfg=b.analyses.CFG(fail_fast=True)
  ```
### surveyors
  #### &nbsp;&nbsp;Surveyors are basic tools for performing symbolic execution with common goals.

### factory
   #### &nbsp;&nbsp;Provides access to important analysis elements such as path groups and symbolic execution results.It is merely a home for all the functions that produce new instances of important angr classes and should be sitting on Project.
   ```python  
   import claripy
   block = b.factory.block(addr=b.entry)
   block = b.factory.block(addr=b.entry, byte_string='\xc3')
   block = b.factory.block(addr=b.entry, num_inst=1)

   state = b.factory.blank_state(addr=b.entry)
   state = b.factory.entry_state(args=['./program', claripy.BVS('arg1', 20*8)])
   state = b.factory.call_state(0x1000, "hello", "world")
   ```
### state  
  
   #### &nbsp;&nbsp;Get state
   ```python
   state=proj.factory.entry_state()
   ```
   #### &nbsp;&nbsp;state info
   ```python
   state.memory.load(b.loader.min_addr(), 5) #memory access
   state.regs.sp #access register
   state.regs.ip #ditto
   state.scratch.tmp_expr(0) #access the temps
   ```

