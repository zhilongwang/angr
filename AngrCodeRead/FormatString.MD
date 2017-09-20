#### FormatParser
&nbsp;&nbsp;simuvex.parseformat  <div id="Inter-Page"></div>

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
  
#### FormatParser
&nbsp;&nbsp;_get_fmt()   

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
