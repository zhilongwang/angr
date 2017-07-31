## Discription of Flags  

###  auto_load_libs

   ####  By default, CLE will attempt to load all the dependencies of the main binary, unless
   ```python
   b = angr.Project("/bin/true", load_options=dict(auto_load_libs=False))
   ```
###  Loading Options  
   #### CLE expects a dict as a set of parameters.  

   ```python
   load_options = {'main_opts':{options0}, 'lib_opts': {libname1:{options1}, path2:{options2}, ...}}

    # Or in a more readable form:
    load_options = {}
    load_options['main_opts'] = {k1:v1, k2:v2 ...}
    load_options['lib_opts'] = {}
    load_options['lib_opts'][path1] = {k1:v1, k2:v2, ...}
    load_options['lib_opts'][path2] = {k1:v1, k2:v2, ...}
   ```
   #### Valid options  
   ```python
   load_options = {}

    # shall we also load dynamic libraries?
    load_options['auto_load_libs'] = False

    # A list of libraries to load regardless of whether they're required by the loaded object
    load_options['force_load_libs'] = ['libleet.so']

    # specific libs to skip
    load_options['skip_libs'] = ['libc.so.6']

    # Options to be used when loading the main binary
    load_options['main_opts'] = {'backend': 'elf'}

    # A dictionary mapping library names to a dictionary of objects to be used when loading them.
    load_options['lib_opts'] = {'libc.so.6': {'custom_base_addr': 0x13370000}}

    # A list of paths we can additionally search for shared libraries
    load_options['custom_ld_path'] = ['/my/fav/libs']

    # Whether libraries with different version numbers in the filename will be considered equivalent, for example libc.so.6 and libc.so.0
    load_options['ignore_import_version_numbers'] = False

    # The alignment to use for rebasing shared objects
    load_options['rebase_granularity'] = 0x1000

    # Throw an Exception if a lib cannot be found (the default is fail silently on missing libs)
    load_options['except_missing_libs'] = True
   ```

###  Symlolic analysis:function summaries  
##### https://docs.angr.io/docs/loading.html