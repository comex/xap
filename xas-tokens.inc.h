  switch (insn[0]) { \
    case 'a': \
      switch (insn[1]) { \
        case 'd': \
          switch (insn[2]) { \
            case 'd': \
              switch (insn[3]) { \
                case '\x00': \
                    goto x_add; \
                case 'c': \
                  if (insn[4] == '\0') \
                    goto x_addc; \
                  break; \
                default: \
                  goto xunknown; \
              } \
              break; \
            default: \
              goto xunknown; \
          } \
          break; \
        case 'n': \
          if (!memcmp(insn + 2, "d", 2)) \
            goto x_and; \
          break; \
        case 's': \
          switch (insn[2]) { \
            case 'l': \
              if (insn[3] == '\0') \
                goto x_asl; \
              break; \
            case 'r': \
              if (insn[3] == '\0') \
                goto x_asr; \
              break; \
            default: \
              goto xunknown; \
          } \
          break; \
        default: \
          goto xunknown; \
      } \
      break; \
    case 'b': \
      switch (insn[1]) { \
        case 'c': \
          switch (insn[2]) { \
            case '\x00': \
                goto x_bc; \
            case '2': \
              if (insn[3] == '\0') \
                goto x_bc2; \
              break; \
            case 'c': \
              if (insn[3] == '\0') \
                goto x_bcc; \
              break; \
            case 's': \
              if (insn[3] == '\0') \
                goto x_bcs; \
              break; \
            case 'z': \
              if (insn[3] == '\0') \
                goto x_bcz; \
              break; \
            default: \
              goto xunknown; \
          } \
          break; \
        case 'e': \
          if (!memcmp(insn + 2, "q", 2)) \
            goto x_beq; \
          break; \
        case 'g': \
          switch (insn[2]) { \
            case 'e': \
              if (insn[3] == '\0') \
                goto x_bge; \
              break; \
            case 't': \
              if (insn[3] == '\0') \
                goto x_bgt; \
              break; \
            default: \
              goto xunknown; \
          } \
          break; \
        case 'l': \
          if (!memcmp(insn + 2, "t", 2)) \
            goto x_blt; \
          break; \
        case 'm': \
          if (!memcmp(insn + 2, "i", 2)) \
            goto x_bmi; \
          break; \
        case 'n': \
          if (!memcmp(insn + 2, "e", 2)) \
            goto x_bne; \
          break; \
        case 'p': \
          if (!memcmp(insn + 2, "l", 2)) \
            goto x_bpl; \
          break; \
        case 'r': \
          switch (insn[2]) { \
            case 'a': \
              if (insn[3] == '\0') \
                goto x_bra; \
              break; \
            case 'k': \
              if (insn[3] == '\0') \
                goto x_brk; \
              break; \
            case 'x': \
              if (!memcmp(insn + 3, "l", 2)) \
                goto x_brxl; \
              break; \
            default: \
              goto xunknown; \
          } \
          break; \
        case 's': \
          if (!memcmp(insn + 2, "r", 2)) \
            goto x_bsr; \
          break; \
        default: \
          goto xunknown; \
      } \
      break; \
    case 'c': \
      if (!memcmp(insn + 1, "mp", 3)) \
        goto x_cmp; \
      break; \
    case 'd': \
      switch (insn[1]) { \
        case 'c': \
          if (insn[2] == '\0') \
            goto x_dc; \
          break; \
        case 's': \
          if (insn[2] == '\0') \
            goto x_ds; \
          break; \
        default: \
          goto xunknown; \
      } \
      break; \
    case 'e': \
      switch (insn[1]) { \
        case 'n': \
          switch (insn[2]) { \
            case 'd': \
              if (!memcmp(insn + 3, "mod", 4)) \
                goto x_endmod; \
              break; \
            case 't': \
              switch (insn[3]) { \
                case 'e': \
                  switch (insn[4]) { \
                    case 'r': \
                      switch (insn[5]) { \
                        case '\x00': \
                            goto x_enter; \
                        case 'l': \
                          if (insn[6] == '\0') \
                            goto x_enterl; \
                          break; \
                        default: \
                          goto xunknown; \
                      } \
                      break; \
                    default: \
                      goto xunknown; \
                  } \
                  break; \
                default: \
                  goto xunknown; \
              } \
              break; \
            default: \
              goto xunknown; \
          } \
          break; \
        default: \
          goto xunknown; \
      } \
      break; \
    case 'l': \
      switch (insn[1]) { \
        case 'd': \
          if (insn[2] == '\0') \
            goto x_ld; \
          break; \
        case 'e': \
          switch (insn[2]) { \
            case 'a': \
              switch (insn[3]) { \
                case 'v': \
                  switch (insn[4]) { \
                    case 'e': \
                      switch (insn[5]) { \
                        case '\x00': \
                            goto x_leave; \
                        case '/': \
                          if (!memcmp(insn + 6, "leavel", 7)) \
                            goto x_leave/leavel; \
                          break; \
                        case 'l': \
                          if (insn[6] == '\0') \
                            goto x_leavel; \
                          break; \
                        default: \
                          goto xunknown; \
                      } \
                      break; \
                    default: \
                      goto xunknown; \
                  } \
                  break; \
                default: \
                  goto xunknown; \
              } \
              break; \
            default: \
              goto xunknown; \
          } \
          break; \
        case 's': \
          switch (insn[2]) { \
            case 'l': \
              if (insn[3] == '\0') \
                goto x_lsl; \
              break; \
            case 'r': \
              if (insn[3] == '\0') \
                goto x_lsr; \
              break; \
            default: \
              goto xunknown; \
          } \
          break; \
        default: \
          goto xunknown; \
      } \
      break; \
    case 'm': \
      if (!memcmp(insn + 1, "odule", 6)) \
        goto x_module; \
      break; \
    case 'n': \
      switch (insn[1]) { \
        case 'a': \
          if (!memcmp(insn + 2, "dd", 3)) \
            goto x_nadd; \
          break; \
        case 'o': \
          if (!memcmp(insn + 2, "p", 2)) \
            goto x_nop; \
          break; \
        default: \
          goto xunknown; \
      } \
      break; \
    case 'o': \
      switch (insn[1]) { \
        case 'r': \
          switch (insn[2]) { \
            case '\x00': \
                goto x_or; \
            case 'g': \
              if (insn[3] == '\0') \
                goto x_org; \
              break; \
            default: \
              goto xunknown; \
          } \
          break; \
        default: \
          goto xunknown; \
      } \
      break; \
    case 'p': \
      if (!memcmp(insn + 1, "rint", 5)) \
        goto x_print; \
      break; \
    case 'r': \
      switch (insn[1]) { \
        case 'e': \
          if (!memcmp(insn + 2, "g", 2)) \
            goto x_reg; \
          break; \
        case 'o': \
          switch (insn[2]) { \
            case 'l': \
              if (insn[3] == '\0') \
                goto x_rol; \
              break; \
            case 'r': \
              if (insn[3] == '\0') \
                goto x_ror; \
              break; \
            default: \
              goto xunknown; \
          } \
          break; \
        case 't': \
          switch (insn[2]) { \
            case 'i': \
              if (insn[3] == '\0') \
                goto x_rti; \
              break; \
            case 's': \
              if (insn[3] == '\0') \
                goto x_rts; \
              break; \
            default: \
              goto xunknown; \
          } \
          break; \
        default: \
          goto xunknown; \
      } \
      break; \
    case 's': \
      switch (insn[1]) { \
        case 'd': \
          if (!memcmp(insn + 2, "iv", 3)) \
            goto x_sdiv; \
          break; \
        case 'i': \
          if (!memcmp(insn + 2, "f", 2)) \
            goto x_sif; \
          break; \
        case 'l': \
          if (!memcmp(insn + 2, "eep", 4)) \
            goto x_sleep; \
          break; \
        case 'm': \
          if (!memcmp(insn + 2, "ult", 4)) \
            goto x_smult; \
          break; \
        case 't': \
          if (insn[2] == '\0') \
            goto x_st; \
          break; \
        case 'u': \
          switch (insn[2]) { \
            case 'b': \
              switch (insn[3]) { \
                case '\x00': \
                    goto x_sub; \
                case 'c': \
                  if (insn[4] == '\0') \
                    goto x_subc; \
                  break; \
                default: \
                  goto xunknown; \
              } \
              break; \
            default: \
              goto xunknown; \
          } \
          break; \
        default: \
          goto xunknown; \
      } \
      break; \
    case 't': \
      if (!memcmp(insn + 1, "st", 3)) \
        goto x_tst; \
      break; \
    case 'u': \
      switch (insn[1]) { \
        case 'd': \
          if (!memcmp(insn + 2, "iv", 3)) \
            goto x_udiv; \
          break; \
        case 'm': \
          if (!memcmp(insn + 2, "ult", 4)) \
            goto x_umult; \
          break; \
        default: \
          goto xunknown; \
      } \
      break; \
    case 'x': \
      if (!memcmp(insn + 1, "or", 3)) \
        goto x_xor; \
      break; \
    default: \
      goto xunknown; \
  }
