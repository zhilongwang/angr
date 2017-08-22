"""
Given a trace file recording entry of each block.
We force angr to follow the traced path and extract constraints whenever updated
"""
import angr

import simuvex

constraints_file = open("./out.txt", "w")

"""
log trace file
"""
def load_trace():
	res = []
	with open("GetPathConstraint/trace.out") as f:
		for line in f:
			if line.startswith('[B_ENT]'):
				addr = int(line[7:7+6], 16)
				res.append(addr)
			elif line.startswith('[C2LIB]') :
				addr = int(0)
				res.append(addr)
	return res

def detect_new_constraints(state):
	global constraints_file
	#constraints_file.write(str(state.se.constraints))
	constraints_file.write(str(state.inspect.added_constraints))
	constraints_file.write("\n")
	for cons in state.inspect.added_constraints:
		constraints_file.write(cons.__repr__(max_depth=2))
	constraints_file.write("\n")

def main():
	# log trace file
	trace_log = load_trace()

	#load binary	
	proj = angr.Project('GetPathConstraint/test', auto_load_libs=False)
	main = proj.loader.main_bin.get_symbol("main")

	#set entry point 
	state = proj.factory.blank_state(addr=main.addr)
	state.inspect.b('constraints', when=simuvex.BP_AFTER, action=detect_new_constraints)
	state.stack_push(0x0)
	p = proj.factory.path(state)
	print("start entry:0x%x" % proj.entry)
	print("main entry:0x%x" % main.addr)

	#match the binary entry with PIN's base block trace
	if p.addr != trace_log[0] :
		print("ERROR: Entrance is not matching, exit")
		exit

	for i in range(1,len(trace_log)):
		pg=p.step() 		#execute one step(one baseblock),and get pathgroup 
		sucs=p.successors 	#get the state group
		inst_addr=trace_log[i] 	#read one of PIN's trace 
		sucs_num=len(sucs)      	#get the lenth of state group
		print("The path has", sucs_num, "successors!")
		print("The length of constraints is", len(p.state.se.constraints))
		print(pg)             	#print the path group
		if inst_addr == 0 :	#skip the lib function
			p=pg[0]		
			pg=p.step()
			p=pg[0]	
			continue
		else:			#choose and step into the match path
			for j in range(sucs_num):
				if sucs[j].addr == inst_addr :
					print("success entry[%d]:%x" % (1,sucs[j].addr))
					p=pg[j]	
					break
	p=p.step()[0]
	for k in range(len(p.addr_trace.hardcopy)):
		print("0x%x" % p.addr_trace.hardcopy[k])
	for step in p.trace:
		print(step)
	print(p.state.posix.dumps(0)) #this can give you concret input values

	global constraints_file
	constraints_file.close()
	return


if __name__ == "__main__":
	main()
