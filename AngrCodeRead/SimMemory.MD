 ## SimMemory
 &nbsp;&nbsp;simuvex.storage.memory        
 #### store()   <div id="store"></div>  

  ```python    
  
    def store(self, addr, data, size=None, condition=None, add_constraints=None, endness=None, action=None,
              inspect=True, priv=None, disable_actions=False):
        """
        Stores content into memory.

        :param addr:        A claripy expression representing the address to store at.
        :param data:        The data to store (claripy expression or something convertable to a claripy expression).
        :param size:        A claripy expression representing the size of the data to store.

        The following parameters are optional.

        :param condition:       A claripy expression representing a condition if the store is conditional.
        :param add_constraints: Add constraints resulting from the merge (default: True).
        :param endness:         The endianness for the data.
        :param action:          A SimActionData to fill out with the final written value and constraints.
        :param bool inspect:    Whether this store should trigger SimInspect breakpoints or not.
        :param bool disable_actions: Whether this store should avoid creating SimActions or not. When set to False,
                                     state options are respected.
        """
        if priv is not None: self.state.scratch.push_priv(priv)

        addr_e = _raw_ast(addr)
        data_e = _raw_ast(data)
        size_e = _raw_ast(size)
        condition_e = _raw_ast(condition)
        add_constraints = True if add_constraints is None else add_constraints

        if isinstance(addr, str):
            named_addr, named_size = self._resolve_location_name(addr)
            addr = named_addr
            addr_e = addr
            if size is None:
                size = named_size
                size_e = size

        # store everything as a BV
        data_e = self._convert_to_ast(data_e, size_e if isinstance(size_e, (int, long)) else None)

        if type(size_e) in (int, long):
            size_e = self.state.se.BVV(size_e, self.state.arch.bits)

        if inspect is True:
            if self.category == 'reg':
                self.state._inspect(
                    'reg_write',
                    BP_BEFORE,
                    reg_write_offset=addr_e,
                    reg_write_length=size_e,
                    reg_write_expr=data_e)
                addr_e = self.state._inspect_getattr('reg_write_offset', addr_e)
                size_e = self.state._inspect_getattr('reg_write_length', size_e)
                data_e = self.state._inspect_getattr('reg_write_expr', data_e)
            elif self.category == 'mem':
                self.state._inspect(
                    'mem_write',
                    BP_BEFORE,
                    mem_write_address=addr_e,
                    mem_write_length=size_e,
                    mem_write_expr=data_e,
                )
                addr_e = self.state._inspect_getattr('mem_write_address', addr_e)
                size_e = self.state._inspect_getattr('mem_write_length', size_e)
                data_e = self.state._inspect_getattr('mem_write_expr', data_e)

        # if the condition is false, bail
        if condition_e is not None and self.state.se.is_false(condition_e):
            if priv is not None: self.state.scratch.pop_priv()
            return

        if (
            o.UNDER_CONSTRAINED_SYMEXEC in self.state.options and
            isinstance(addr_e, claripy.ast.Base) and
            addr_e.uninitialized
        ):
            self._constrain_underconstrained_index(addr_e)

        request = MemoryStoreRequest(addr_e, data=data_e, size=size_e, condition=condition_e, endness=endness)
        self._store(request)

        if inspect is True:
            if self.category == 'reg': self.state._inspect('reg_write', BP_AFTER)
            if self.category == 'mem': self.state._inspect('mem_write', BP_AFTER)

        add_constraints = self.state._inspect_getattr('address_concretization_add_constraints', add_constraints)
        if add_constraints and len(request.constraints) > 0:
            self.state.add_constraints(*request.constraints)

        if not disable_actions:
            if request.completed and o.AUTO_REFS in self.state.options and action is None and not self._abstract_backer:
                ref_size = size * 8 if size is not None else data_e.size()
                region_type = self.category
                if region_type == 'file':
                    # Special handling for files to keep compatibility
                    # We may use some refactoring later
                    region_type = self.id
                action = SimActionData(self.state, region_type, 'write', addr=addr_e, data=data_e, size=ref_size,
                                       condition=condition
                                       )
                self.state.log.add_action(action)

            if request.completed and action is not None:
                action.actual_addrs = request.actual_addresses
                action.actual_value = action._make_object(request.stored_values[0]) # TODO
                if len(request.constraints) > 0:
                    action.added_constraints = action._make_object(self.state.se.And(*request.constraints))
                else:
                    action.added_constraints = action._make_object(self.state.se.true)

        if priv is not None: self.state.scratch.pop_priv()  
  ```
