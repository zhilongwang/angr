# Symbolic Execution - Surveyors
&nbsp;&nbsp;&nbsp;&nbsp;At heart, angr is a symbolic execution engine.

## &nbsp;&nbsp;1.Surveyor 
&nbsp;&nbsp;&nbsp;&nbsp;Surveyor are an old API that is rather unwieldy.It's recommended to use PathGroups instead.  
## &nbsp;&nbsp;2.PathGroups  
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

   ```python
   # Run a quick execution!
   pg = project.factory.path_group()
   pg.run()  # step until no more active paths
   ```
## &nbsp;&nbsp;3.PathGroup.Explorer() 
&nbsp;&nbsp;&nbsp;&nbsp;Pathgroups are supposed to replace surveyors.Explorer, being more clever and efficient.   

   ``` python
    ## crackme0x00a is at: https://github.com/angr/angr-doc/raw/master/examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a
    import angr

    FIND_ADDR = 0x08048533 # mov dword [esp], str.Congrats_ ; [0x8048654:4]=0x676e6f43 LEA str.Congrats_ ; "Congrats!" @ 0x8048654
    AVOID_ADDR = 0x08048554 # mov dword [esp], str.Wrong_ ; [0x804865e:4]=0x6e6f7257 LEA str.Wrong_ ; "Wrong!" @ 0x804865e


    def main():
        proj = angr.Project('crackme0x00a', load_options={"auto_load_libs": False})
        pg = proj.factory.path_group()

        ### case one
        pg.explore(find=FIND_ADDR, avoid=AVOID_ADDR)
        return pg.found[0].state.posix.dumps(0).split('\0')[0] # stdin
        ### case two
        pg.explore(find=lambda p: "Congrats" in p.state.posix.dumps(1))
        s = pg.found[0].state
        print s.posix.dumps(1)
        flag = s.posix.dumps(0)
        print(flag)
        ###

    def test():
        assert main() == 'g00dJ0B!'

    if __name__ == '__main__':
        print(main())  
   ```  
&nbsp;&nbsp;&nbsp;&nbsp;p.state.posix.dumps(1) is the str() of output.  
&nbsp;&nbsp;&nbsp;&nbsp;p.state.posix.dumps(0) is the str() of input.

## &nbsp;&nbsp;4.Stash types  
&nbsp;&nbsp;&nbsp;&nbsp;https://docs.angr.io/docs/pathgroups.html


### &nbsp;&nbsp; path_group.move
&nbsp;&nbsp;&nbsp;&nbsp;You can move paths between stashes by using the path_group.move function. This function accepts many options to control which paths are moved between which stashes.  
## &nbsp;&nbsp;4.PathGroup.step()   

&nbsp;&nbsp;&nbsp;&nbsp; 1.End user calls step()

&nbsp;&nbsp;&nbsp;&nbsp; 2.step() calls _one_step()

&nbsp;&nbsp;&nbsp;&nbsp; 3._one_step() pops a single exploration technique from the list of active step exploration technique callbacks, and calls it with the path group we are operating on

&nbsp;&nbsp;&nbsp;&nbsp; 4.This callback calls step() on the path group that it gets called with

&nbsp;&nbsp;&nbsp;&nbsp; 5.This process repeats until there are no more callbacks

## &nbsp;&nbsp;5.Simulateion Managers(simgr)

&nbsp;&nbsp;&nbsp;&nbsp; https://github.com/angr/angr-doc/blob/master/docs/toplevel.md  
   ```python
   simgr = proj.factory.simgr(state) # TODO: change name before merge
   <SimulationManager with 1 active>
   simgr.active
   [<SimState @ 0x401670>]

   simgr.step()
    simgr.active
    [<SimState @ 0x1020300>]
    simgr.active[0].regs.rip   # new and exciting!
    <BV64 0x1020300>
   ```