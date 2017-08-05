# Symbolic Simuvex-Data Type  




   ```python
   #This helps with getting instances of type objects
    import simuvex
    print simuvex.parse_type('int')
    print simuvex.parse_type('char **')
    print simuvex.parse_type('struct aa {int x; long y;}')
    print simuvex.parse_type('struct aa {int x; long y;}').fields

    defs = simuvex.parse_types("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
    print defs
    print defs['list_node'].fields
    print defs['list_node'].fields['next'].pts_to.fields
    # If you want to get a function type and you don't want to construct it manually,
    # you have to use parse_defns, not parse_type
    print simuvex.parse_defns("int x(int y, double z);")
    #you can register struct definitions for future use:
    simuvex.define_struct('struct abcd { int x; int y; }')
    simuvex.register_types(simuvex.parse_types('typedef long time_t;'))
    print simuvex.parse_defns('struct abcd a; time_t b;')   

   ```   
&nbsp;&nbsp;&nbsp;&nbsp;1.You first use [array index notation] to specify the address you'd like to load from

&nbsp;&nbsp;&nbsp;&nbsp;2.If at that address is a pointer, you may access the deref property to return a SimMemView at the address present in memory.  

&nbsp;&nbsp;&nbsp;&nbsp;3.You then specify a type for the data by simply accessing a property of that name. For a list of supported types, look at state.mem.types.  
&nbsp;&nbsp;&nbsp;&nbsp;4.You can then refine the type. Any type may support any refinement it likes. Right now the only refinements supported are that you may access any member of a struct by its member name, and you may index into a string or array to access that element. 

&nbsp;&nbsp;&nbsp;&nbsp;5.If the address you specified initially points to an array of that type, you can say .array(n) to view the data as an array of n elements.

&nbsp;&nbsp;&nbsp;&nbsp;6.Finally, extract the structured data with .resolved or .concrete. .resolved will return bitvector values, while .concrete will return integer, string, array, etc values, whatever best represents the data. 

&nbsp;&nbsp;&nbsp;&nbsp;7.Alternately, you may store a value to memory, by assigning to the chain of properties that you've constructed. Note that because of the way python works, x = s.mem[...].prop; x = val will NOT work, you must say s.mem[...].prop = val.


   ```python

    import angr
    b = angr.Project('examples/fauxware/fauxware')
    s = b.factory.entry_state()
    s.mem[0x601048]
    <<untyped> <unresolvable> at 0x601048>

    s.mem[0x601048].int
    <int (32 bits) <BV32 0x4008d0> at 0x601048>

    s.mem[0x601048].long
    <long (64 bits) <BV64 0x4008d0> at 0x601048>

    s.mem[0x601048].long.resolved
    <BV64 0x4008d0>

    s.mem[0x601048].long.concrete
    4196560L

    s.mem[0x601048].deref
    <<untyped> <unresolvable> at 0x4008d0>

    s.mem[0x601048].deref.string
    <string_t <BV64 0x534f534e45414b59> at 0x4008d0>

    s.mem[0x601048].deref.string.resolved
    <BV64 0x534f534e45414b59>

    s.mem[0x601048].deref.string.concrete
    'SOSNEAKY'
   ```