## FormatParser
&nbsp;&nbsp;simuvex.parseformat  <div id="Inter-Page"></div>
#### _parse()   
  ```python
      def _parse(self, fmt_idx):
        """
        Parse format strings.

        :param fmt_idx: The index of the (pointer to the) format string in the arguments list.
        :returns:       A FormatString object which can be used for replacing the format specifiers with arguments or
                        for scanning into arguments.
        """

        fmtstr_ptr = self.arg(fmt_idx)

        if self.state.se.symbolic(fmtstr_ptr):
            raise SimProcedureError("Symbolic pointer to (format) string :(")

        length = self._sim_strlen(fmtstr_ptr)
        if self.state.se.symbolic(length):
            all_lengths = self.state.se.any_n_int(length, 2)
            if len(all_lengths) != 1:
                raise SimProcedureError("Symbolic (format) string, game over :(")
            length = all_lengths[0]

        if self.state.se.is_true(length == 0):
            return FormatString(self, [""])

        fmt_xpr = self.state.memory.load(fmtstr_ptr, length)

        fmt = [ ]
        for i in xrange(fmt_xpr.size(), 0, -8):
            char = fmt_xpr[i - 1 : i - 8]
            concrete_chars = self.state.se.any_n_int(char, 2)
            if len(concrete_chars) == 1:
                # Concrete chars are directly appended to the list
                fmt.append(chr(concrete_chars[0]))
            else:
                # For symbolic chars, just keep them symbolic
                fmt.append(char)

        # make a FormatString object
        fmt_str = self._get_fmt(fmt)

        l.debug("Fmt: %r", fmt_str)

        return fmt_str
  ```    
  
#### _get_fmt()  
&nbsp;&nbsp; 

 ```python   
  
def _get_fmt(self, fmt):
        """
        Extract the actual formats from the format string `fmt`.

        :param list fmt: A list of format chars.
        :returns: a FormatString object
        """

        # iterate over the format string looking for format specifiers
        components = [ ]
        i = 0
        while i < len(fmt):
            if type(fmt[i]) is str and fmt[i] == "%":
                # Note that we only support concrete format specifiers
                # grab the specifier
                # go to the space
                specifier = ""
                for c in fmt[i+1:]:
                    if type(c) is str:
                        specifier += c
                    else:
                        break

                specifier = self._match_spec(specifier)
                if specifier is not None:
                    i += len(specifier)
                    components.append(specifier)
                else:
                    # if we get here we didn't match any specs, the first char will be thrown away
                    # and we'll add the percent
                    i += 1
                    components.append('%')
            else:
                # claripy ASTs, which are usually symbolic variables
                # They will be kept as they are - even if those chars can be evaluated to "%"
                components.append(fmt[i])
            i += 1

        return FormatString(self, components)
  ```
## FormatString
#### interpret() 
&nbsp;&nbsp;      
 ```python   
    def interpret(self, addr, startpos, args, region=None):
        """
        Interpret a format string, reading the data at `addr` in `region` into `args` starting at `startpos`.
        """

        # TODO: we only support one format specifier in interpretation for now
        #filter the item in self.components with condition: isinstance(x,FormatSpecifier)
        format_specifier_count = len(filter(lambda x: isinstance(x, FormatSpecifier), self.components))
        if format_specifier_count > 1:
            l.warning("We don't support more than one format specifiers in format strings.")

        if region is None:
            region = self.parser.state.memory

        bits = self.parser.state.arch.bits
        failed = self.parser.state.se.BVV(0, bits)
        argpos = startpos 
        position = addr
        print("Debug: in simuvex/engines/engine.py.process constraints_len %d" % len(self.parser.state.se.constraints))
        for component in self.components:
            if isinstance(component, str):
                # TODO we skip non-format-specifiers in format string interpretation for now
                # if the region doesn't match the concrete component, we need to return immediately
                pass
            else:
                print(component)
                fmt_spec = component
                try:
                    dest = args(argpos)
                except SimProcedureArgumentError:
                    dest = None
                if fmt_spec.spec_type == 's':
                    # set some limits for the find

                    max_str_len = self.parser.state.libc.max_str_len
                    max_sym_bytes = self.parser.state.libc.buf_symbolic_bytes

                    # has the length of the format been limited by the string itself?
                    if fmt_spec.length_spec is not None:
                        max_str_len = fmt_spec.length_spec
                        max_sym_bytes = fmt_spec.length_spec

                    # TODO: look for limits on other characters which scanf is sensitive to, '\x00', '\x20'
                    ohr, ohc, ohi = region.find(position, self.parser.state.se.BVV('\n'), max_str_len, max_symbolic_bytes=max_sym_bytes)

                    # if no newline is found, mm is position + max_strlen
                    # If-branch will really only happen for format specifiers with a length
                    mm = self.parser.state.se.If(ohr == 0, position + max_str_len, ohr)
                    # we're just going to concretize the length, load will do this anyways
                    length = self.parser.state.se.max_int(mm - position)
                    src_str = region.load(position, length)

                    # TODO all of these should be delimiters we search for above
                    # add that the contents of the string cannot be any scanf %s string delimiters
                    for delimiter in set(FormatString.SCANF_DELIMITERS) - {'\x00'}:
                        delim_bvv = self.parser.state.se.BVV(delimiter)
                        for i in range(length):
                            self.parser.state.add_constraints(region.load(position + i, 1) != delim_bvv)

                    # write it out to the pointer
                    self.parser.state.memory.store(dest, src_str)
                    # store the terminating null byte
                    self.parser.state.memory.store(dest + length, self.parser.state.se.BVV(0, 8))

                    position += length

                else:

                    # XXX: atoi only supports strings of one byte
                    if fmt_spec.spec_type in ['d', 'u', 'x']:

                        base = 16 if fmt_spec.spec_type == 'x' else 10
                        print("base: %d" % base)
                        status, i, num_bytes = self.parser._sim_atoi_inner(position, region, base=base, read_length=fmt_spec.length_spec)
                        # increase failed count if we were unable to parse it
                        
                        failed = self.parser.state.se.If(status, failed, failed + 1)
                        position += num_bytes
                    elif fmt_spec.spec_type == 'c':
                        i = region.load(position, 1)
                        i = i.zero_extend(bits - 8)
                        position += 1
                    else:
                        raise SimProcedureError("unsupported format spec '%s' in interpret" % fmt_spec.spec_type)
                    
                    i = self.parser.state.se.Extract(fmt_spec.size*8-1, 0, i)
                    self.parser.state.memory.store(dest, i, size=fmt_spec.size, endness=self.parser.state.arch.memory_endness)
                argpos += 1
        # we return (new position, number of items parsed)
        # new position is used for interpreting from a file, so we can increase file position
        return (position, ((argpos - startpos) - failed))
 ```
