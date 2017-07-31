## Discription of main class  

### project   

  #### new project
  ```python
  b = angr.Project('/bin/true')
  b.arch #architecture
  b.entry #entry address
  b.filname
  b.loader #load address
  ```
  #### loader
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

### factory
   #### Provides access to important analysis elements such as path groups and symbolic execution results.
   ```python  
   proj.factory.successors() #Perform execution using any applicable engine. Return a SimSuccessors object classifying the results of the run.
   proj.factory.blank_state() #Returns a mostly-uninitialized state object
   proj.factory.entry_state() #Returns a state object representing the program at its entry point.
   proj.factory.full_init_state() #Very much like entry_state(), except that instead of starting execution at the program entry point, execution begins at a special SimProcedure that plays the role of the dynamic loader, calling each of the initializer functions that should be called before execution reaches the entry point.
   proj.factory.call_state() #Returns a state object initialized to the start of a given function, as if it were called with given parameters.
   proj.factory.path() 
   proj.factory.path_group()
   ```
### state  
  
   #### Get state
   ```python
   state=proj.factory.entry_state()
   ```
   #### state info
   ```python
   state.memory.load(b.loader.min_addr(), 5) #memory access
   state.regs.sp #access register
   state.regs.ip #ditto
   state.scratch.tmp_expr(0) #access the temps
   ```

