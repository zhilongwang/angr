## Discription of plugins  

### 1.plugins   

  #### &nbsp;&nbsp;Plugins essentially let you make class variables and functions available to a simuvex state object in a customizable and usually persistent way.

All plugins must subclass SimStatePlugin and implement copy(), merge(), and widen().

Your plugin file should be located in the plugins folder: simuvex/plugins. All plugins must be registered. You can register your plugin by calling SimStatePlugin.register_default() (example). You must also add a property to the s_state file (example). You might also want to add a line to __init__.py if you want to make you plugin class or other global variables available to you or other modules when importing the plugin package as a whole. Once registered, your plugin class instance will be available in the state object via state.plugin_name. See here and here.

I would recommend referencing some of the more easy to understand plugins as examples: libc, and posix. You can find uses of these plugins in many SimProcedures.

Kind of an edge case but added for completeness: If you want to include non-python files with your plugin (e.g., data files that you intend to reference) and have those files copied over during the simuvex installation process, you must edit package_data in setup.py.

I might be forgetting something; feel free to chime in. When complete, this should go in the docs somewhere. Since there are so many steps touching a lot files, perhaps a walkthrough that creates an example plugin might be in order.
 
  #### &nbsp;&nbsp;loader
 
### 2.analyses  
  #### &nbsp;&nbsp;
