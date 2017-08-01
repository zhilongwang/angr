# Symbolic Execution - Surveyors
&nbsp;&nbsp;&nbsp;&nbsp;At heart, angr is a symbolic execution engine.

## &nbsp;&nbsp;Surveyor 
&nbsp;&nbsp;&nbsp;&nbsp;Surveyor are an old API that is rather unwieldy.It's recommended to use PathGroups instead.  
## &nbsp;&nbsp;PathGroups  
&nbsp;&nbsp;&nbsp;&nbsp;Path groups are just a bunch of paths being executed at once. 

### &nbsp;&nbsp; Some basic examples of pathgroups capabilities.  

   ```python
   import angr
   p = angr.Project('examples/fauxware/fauxware', load_options={'auto_load_libs': False})
   pg = p.factory.path_group()
   while len(pg.active) > 0:
        pg.step()
   print (pg)
   "<PathGroup with 1 deadended>"

   # We now have a deadended path, let's see what we can do with it.
   path = pg.deadended[0]
   print('Path length: {0} steps'.format(path.length))
   "Path length: 51 steps"

   #Get path trace:
   print('Trace:')
   for step in path.trace:
        print(step)

   #Get constraints applied to the path:
   print('There are %d constraints.' % len(path.state.se.constraints))
   "There are 2 constraints."   

   #Get memory state at the end of the traversal:
   print('rax: {0}'.format(path.state.regs.rax))
   "rax: <BV64 0x37>"
   assert path.state.se.any_int(path.state.regs.rip) == path.addr  # regs are BitVectors
   ```
   