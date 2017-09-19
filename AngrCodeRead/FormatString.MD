#### FormatParser
&nbsp;&nbsp;simuvex.parseformat  

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

[ROP__ARM](#parse)
