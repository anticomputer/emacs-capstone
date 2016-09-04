/* 

This is an emacs25 module providing an elisp interface into the libcapstone 
disassembly engine (http://www.capstone-engine.org). Hopefully you'll find
it use for it in your travels.

- bas@collarchoke.org 09/04/2016

PS: I don't know how licenses work, whatever is the most free, apply that.

TODO: implement the cs detail API for more in depth code analysis support

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <emacs-module.h>
/* see this for C api documentation */
#include <capstone.h>

int plugin_is_GPL_compatible;

static emacs_value
Fcall_cs_version(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    unsigned int ret = cs_version(NULL, NULL); 
    return env->make_integer(env, ret); 
}

static emacs_value
Fcall_cs_support(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    bool ret;
    int query = (int)env->extract_integer(env, args[0]);

    ret = cs_support(query);

    return env->make_integer(env, ret);
}

static emacs_value
Fcall_cs_open(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    cs_err ret = CS_ERR_OK;
    cs_arch arch = (cs_arch)env->extract_integer(env, args[0]); 
    cs_mode mode = (cs_mode)env->extract_integer(env, args[1]); 
    csh handle = 0;

    ret = cs_open(arch, mode, &handle);

    /* return the handle on success, nil on failure */
    if (ret == CS_ERR_OK) {
        return env->make_integer(env, handle);
    } else {
        /* explicitly check all error values before accepting ret as handle */
        return env->make_integer(env, ret);
    }
}

static emacs_value
Fcall_cs_close(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    cs_err ret;
    csh handle = (csh)env->extract_integer(env, args[0]);

    ret = cs_close(&handle);

    return env->make_integer(env, ret); 
}

static emacs_value
Fcall_cs_option(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    cs_err ret;
    csh handle = (csh)env->extract_integer(env, args[0]);
    cs_opt_type type = (cs_opt_type)env->extract_integer(env, args[1]);
    size_t value = (size_t)env->extract_integer(env, args[2]);

    ret = cs_option(handle, type, value);

    return env->make_integer(env, ret);
}

static emacs_value
Fcall_cs_errno(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    cs_err ret;
    csh handle = (csh)env->extract_integer(env, args[0]);

    ret = cs_errno(handle);

    return env->make_integer(env, ret); 
}

static emacs_value
Fcall_cs_strerror(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    const char *ret;
    cs_err code = (cs_err)env->extract_integer(env, args[0]);

    ret = cs_strerror(code);
    if (ret != NULL) {
        return env->make_string(env, ret, strlen(ret));
    }
    else {
        return env->intern(env, "nil");
    }
}

static emacs_value
Fcall_cs_reg_name(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    const char *ret;
    csh handle = (csh)env->extract_integer(env, args[0]);
    unsigned int reg_id = (unsigned int)env->extract_integer(env, args[1]);

    ret = cs_reg_name(handle, reg_id);
    if (ret != NULL) {
        return env->make_string(env, ret, strlen(ret));
    } else {
        return env->intern(env, "nil");
    }
}

static emacs_value
Fcall_cs_insn_name(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    const char *ret;
    csh handle = (csh)env->extract_integer(env, args[0]);
    unsigned int insn_id = (unsigned int)env->extract_integer(env, args[1]);

    ret = cs_insn_name(handle, insn_id);
    if (ret != NULL) {
        return env->make_string(env, ret, strlen(ret));
    } else {
        return env->intern(env, "nil");
    }
}

static emacs_value
Fcall_cs_group_name(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    const char *ret;
    csh handle = (csh)env->extract_integer(env, args[0]);
    unsigned int group_id = (unsigned int)env->extract_integer(env, args[1]);

    ret = cs_group_name(handle, group_id);
    if (ret != NULL) {
        return env->make_string(env, ret, strlen(ret));
    } else {
        return env->intern(env, "nil");
    }
}

static emacs_value
Fcall_cs_disasm(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    size_t ret;
    csh handle = (csh)env->extract_integer(env, args[0]);
    uint8_t *code;
    emacs_value code_vector = args[1];
    size_t code_size = (size_t)env->vec_size(env, args[1]); 
    uint64_t address = (uint64_t)env->extract_integer(env, args[2]);
    size_t count = (size_t)env->extract_integer(env, args[3]);
    cs_insn *insn; 
    emacs_value cs_insn_list_list = env->intern(env, "nil");

    /* allocate the raw code buf */
    code = malloc(code_size); 
    if (code == NULL) {
        return env->intern(env, "nil");
    }
    
    /* turn vector of raw data into code buffer */
    for (int i = 0; i < code_size; i ++) {
        *(code+i) = (uint8_t)env->extract_integer(env,
                                                  env->vec_get(env, code_vector, i));
    } 
    
    /* do the damn thang */ 
    ret = cs_disasm(handle, code, code_size, address, count, &insn); 

    /* don't need this anymore */
    free(code);
    
    if (ret == 0) {
        /* you can call cs_errno() for error code for this case */ 
        return env->intern(env, "nil");
    }

    /* ok, now we have ret number of instructions in insn of type cs_insn */
    
    /* we'll build a list of insn lists ... in reverse so the cons order is right */
    for (int i = ret - 1; i >= 0; i --) {
        emacs_value cs_insn_args[6];
        emacs_value cs_insn_list;
        emacs_value cs_opcode_list = env->intern(env, "nil");
        
        /*  skipping cs_detail for now ... their python bindings don't support it either */
        cs_insn_args[0] = env->make_integer(env, insn[i].id);
        cs_insn_args[1] = env->make_integer(env, insn[i].address);
        cs_insn_args[2] = env->make_integer(env, insn[i].size);
        /* turn opcode array into list of integers */ 
        for (int x = insn[i].size - 1; x >= 0; x --) {
            if (x == insn[i].size - 1) {
                emacs_value opcode_int = env->make_integer(env, (uint8_t)insn[i].bytes[x]);
                cs_opcode_list = env->funcall(env,
                                              env->intern(env, "list"),
                                              1,
                                              &opcode_int);
            } else {
                emacs_value cons_args[2]; 
                cons_args[0] = env->make_integer(env, (uint8_t)insn[i].bytes[x]);
                cons_args[1] = cs_opcode_list;
                cs_opcode_list = env->funcall(env,
                                              env->intern(env, "cons"),
                                              2,
                                              cons_args);
            }
        }
        cs_insn_args[3] = cs_opcode_list; 
        cs_insn_args[4] = env->make_string(env, insn[i].mnemonic, strlen(insn[i].mnemonic));
        cs_insn_args[5] = env->make_string(env, insn[i].op_str, strlen(insn[i].op_str));
        cs_insn_list = env->funcall(env,
                                    env->intern(env, "list"),
                                    6,
                                    cs_insn_args);
        if (i == ret - 1) {
            /* init a list of lists with the first insn */ 
            cs_insn_list_list = env->funcall(env,
                                             env->intern(env, "list"),
                                             1,
                                             &cs_insn_list); 
        } 
        else {
            /* cons to result list */
            emacs_value cons_args[2];
            cons_args[0] = cs_insn_list;
            cons_args[1] = cs_insn_list_list;
            cs_insn_list_list = env->funcall(env,
                                             env->intern(env, "cons"),
                                             2,
                                             cons_args);
        } 
    }

    /* we're done at the native layer with this stuff, so free it */
    cs_free(insn, ret);
    
    /* this is in reverse order, deal with in lisp layer */
    return cs_insn_list_list;
}

int
emacs_module_init(struct emacs_runtime *ert)
{
    emacs_env *env = ert->get_environment(ert);
    emacs_value fset_args[2];

        /* bind capstone lambda()'s to intern'd symbols */

        /* cs_version:capstone--cs-version */
        fset_args[0] = env->intern(env, "capstone--cs-version");
        fset_args[1] = env->make_function(env,
                                          0,
                                          0,
                                          Fcall_cs_version,
                                          "Return combined cs api version",
                                          NULL); 
        env->funcall(env, env->intern(env, "fset"), 2, fset_args);

    /* cs_support:capstone--cs-support */
    fset_args[0] = env->intern(env, "capstone--cs-support");
    fset_args[1] = env->make_function(env,
                                      1,
                                      1,
                                      Fcall_cs_support,
                                      "Check cs for enabled support of ARCH",
                                      NULL);
    env->funcall(env, env->intern(env, "fset"), 2, fset_args);

    /* cs_open:capstone--cs-open */
    fset_args[0] = env->intern(env, "capstone--cs-open");
    fset_args[1] = env->make_function(env,
                                      2,
                                      2,
                                      Fcall_cs_open,
                                      "Initialize cs handle to ARCH and MODE",
                                      NULL);
    env->funcall(env, env->intern(env, "fset"), 2, fset_args);

    /* cs_close:capstone--cs-close */
    fset_args[0] = env->intern(env, "capstone--cs-close");
    fset_args[1] = env->make_function(env,
                                      1,
                                      1,
                                      Fcall_cs_close,
                                      "Close cs handle (careful, frees internals)",
                                      NULL);
    env->funcall(env, env->intern(env, "fset"), 2, fset_args);

    /* cs_option:capstone--cs-option */
    fset_args[0] = env->intern(env, "capstone--cs-option");
    fset_args[1] = env->make_function(env,
                                      3,
                                      3,
                                      Fcall_cs_option,
                                      "Set option on cs HANDLE of TYPE and VALUE",
                                      NULL);
    env->funcall(env, env->intern(env, "fset"), 2, fset_args);
   
    /* cs_errno:capstone--cs-errno */
    fset_args[0] = env->intern(env, "capstone--cs-errno");
    fset_args[1] = env->make_function(env,
                                      1,
                                      1,
                                      Fcall_cs_errno,
                                      "Report the last cs error from HANDLE",
                                      NULL);
    env->funcall(env, env->intern(env, "fset"), 2, fset_args);

    /* cs_strerror:capstone--cs-strerror */
    fset_args[0] = env->intern(env, "capstone--cs-strerror");
    fset_args[1] = env->make_function(env,
                                      1,
                                      1,
                                      Fcall_cs_strerror,
                                      "Return a string describing given error CODE",
                                      NULL);
    env->funcall(env, env->intern(env, "fset"), 2, fset_args);

    /* cs_reg_name:capstone--cs-reg-name */
    fset_args[0] = env->intern(env, "capstone--cs-reg-name");
    fset_args[1] = env->make_function(env,
                                      2,
                                      2,
                                      Fcall_cs_reg_name,
                                      "Using cs HANDLE return string name of REGISTER_ID",
                                      NULL);
    env->funcall(env, env->intern(env, "fset"), 2, fset_args);

    /* cs_insn_name:capstone--cs-insn-name */
    fset_args[0] = env->intern(env, "capstone--cs-insn-name");
    fset_args[1] = env->make_function(env,
                                      2,
                                      2,
                                      Fcall_cs_insn_name,
                                      "Using cs HANDLE return string name of INSN_ID",
                                      NULL);
    env->funcall(env, env->intern(env, "fset"), 2, fset_args);

    /* cs_group_name:capstone--cs-group-name */
    fset_args[0] = env->intern(env, "capstone--cs-group-name");
    fset_args[1] = env->make_function(env,
                                      2,
                                      2,
                                      Fcall_cs_group_name,
                                      "Using cs HANDLE return string name of GROUP_ID",
                                      NULL);
    env->funcall(env, env->intern(env, "fset"), 2, fset_args);
    
    /* cs_disasm:capstone--cs-disasm (not supporting the _iter variant, moot) */
    fset_args[0] = env->intern(env, "capstone--cs-disasm");
    fset_args[1] = env->make_function(env,
                                      4,
                                      4,
                                      Fcall_cs_disasm,
                                      "Using cs HANDLE disassemble vector CODE labeled as starting at ADDRESS for COUNT number of instructions (0 for all)",
                                      NULL);
    env->funcall(env, env->intern(env, "fset"), 2, fset_args);

    /* 
     * NOTE: not supporting the detail API right now, this includes:
     * 
     * cs_op_index, cs_op_count, cs_reg_write, cs_reg_read, cs_insn_group
     *
     * will get to that on another weekend, don't need it right this second
     */


    /* provide capstone-core */ 
    emacs_value Qfeat = env->intern(env, "capstone-core");
    emacs_value Qprovide = env->intern(env, "provide");
    emacs_value provide_args[] = { Qfeat };
    env->funcall(env, Qprovide, 1, provide_args);

    return 0;
}
