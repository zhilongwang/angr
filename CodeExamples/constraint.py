import angr, monkeyhex
proj= angr.Project('test')
state=proj.factory.entry_state()
#64-bit bitvectors with concrete values 1 and 100
one=state.solver.BVV(1,64)
print(one)
one_hundred= state.solver.BVV(100, 64)
print(one_hundred)


print(one+one_hundred)
print(one_hundred+0x100)
print(one_hundred-200*one)

weird_nine=state.solver.BVV(9, 27)
weird_nine.zero_extend(64-27)
print(weird_nine)
weird_nine.sign_extend(64-27)

#symbols value
x=state.solver.BVS("x",64)
print(x)
y=state.solver.BVS("y",64)
print(y)

print(x+one)

print((x+one)/2)

tree=(x+1)/(y+1)
print(tree)
print(tree.op)
print(tree.args)
print(tree.args[0].op)
print(tree.args[0].args)

#symbolic constraints

print(x==1)
print(x==one)
print(x>2)
print(x+y ==one_hundred+5)
print(one_hundred>5)
print(one_hundred>-5) #usigned comparisons
print(one_hundred.SGT(-5)) #signed comparisons

yes=one==1
print(one==1)
print(yes.is_true())
print(yes.is_false())

#constraint solving

state.add_constraints(x>y)
state.add_constraints(y>2)
state.add_constraints(10>x)
print(state.solver.any_int(x))
print(state.solver.any_int(y))

state=proj.factory.entry_state()
input=state.solver.BVS('input',64)
operation=(((input+4)*3)>>1)+input
output=200
state.add_constraints(operation==output)
print("0x%x" % state.se.any_int(input))

state.add_constraints(input<2**32)
print(state.satisfiable())



