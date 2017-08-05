# Hooks
&nbsp;&nbsp;&nbsp;&nbsp;Hooks in angr are very powerful! You can use them to modify a program's behavior in any way you could imagine. 

## &nbsp;&nbsp;1.Hook example  
&nbsp;&nbsp;&nbsp;&nbsp; whenever program execution reaches the main function, instead of executing the actual main function, it will execute this procedure! This procedure just prints out a message, and returns.

   ```python
   from simuvex import SimProcedure
   from angr import Hook, Project
   project = Project('examples/fauxware/fauxware')

   class BugFree(SimProcedure):
       def run(self, argc, argv):
          print 'Program running with argc=%s and argv=%s' % (argc, argv)
          return 0

    # this assumes we have symbols for the binary
   project.hook(project.kb.labels.lookup('main'), Hook(BugFree))

   # Run a quick execution!
   pg = project.factory.path_group()
   pg.run()  # step until no more active paths
    Program running with argc=<SAO <BV64 0x0>> and argv=<SAO <BV64 0x7fffffffffeffa0>>
    <PathGroup with 1 deadended>
   ```  

## &nbsp;&nbsp;2.SimProcedure and Hook 
&nbsp;&nbsp;&nbsp;&nbsp;1. **SimProcedure** is a simuvex class that describes a set of actions to take on a state. Its crux is the run() method.  
&nbsp;&nbsp;&nbsp;&nbsp;2. **Hook** is an angr class that holds a SimProcedure along with information about how to instantiate it.