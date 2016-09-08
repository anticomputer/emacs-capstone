/* 

This is an emacs25 module providing an elisp interface into the libcapstone 
disassembly engine (http://www.capstone-engine.org). Hopefully you'll find
use for it in your travels.

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

/* got tired of typing "env" */
#define _CS_INTERN(s) env->intern(env, s)
#define _CS_NIL() _CS_INTERN("nil")
#define _CS_INT(i) env->make_integer(env, i)
#define _CS_PULL_INT(a) env->extract_integer(env, a)
#define _CS_STRING(s, n) env->make_string(env, s, n) 
#define _CS_VEC_SIZE(v) env->vec_size(env, v)
#define _CS_VEC_GET(v, i) env->vec_get(env, v, i)
#define _CS_MAKE_FUNC(min, max, c_func, doc, data) env->make_function(env, min, max, c_func, doc, data)

/* this requires static arrays */
#define _CS_FUNCALL(func, args)                                 \
    ({                                                          \
        env->funcall(env, env->intern(env, func),               \
                     sizeof(args)/sizeof(emacs_value),          \
                     args);                                     \
    })

static emacs_value
Fcall_cs_version(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    unsigned int ret = cs_version(NULL, NULL); 
    return _CS_INT(ret); 
}

static emacs_value
Fcall_cs_support(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    bool ret;
    int query = (int)_CS_PULL_INT(args[0]);
    
    ret = cs_support(query);
    
    return _CS_INT(ret);
}

static emacs_value
Fcall_cs_open(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    cs_err ret = CS_ERR_OK;
    cs_arch arch = (cs_arch)_CS_PULL_INT(args[0]); 
    cs_mode mode = (cs_mode)_CS_PULL_INT(args[1]); 
    csh handle = 0;

    ret = cs_open(arch, mode, &handle);

    /* return the handle on success, nil on failure */
    if (ret == CS_ERR_OK) {
        return _CS_INT(handle);
    } else {
        /* explicitly check all error values before accepting ret as handle */
        return _CS_INT(ret);
    }
}

static emacs_value
Fcall_cs_close(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    cs_err ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);

    ret = cs_close(&handle);

    return _CS_INT(ret); 
}

static emacs_value
Fcall_cs_option(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    cs_err ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);
    cs_opt_type type = (cs_opt_type)_CS_PULL_INT(args[1]);
    size_t value = (size_t)_CS_PULL_INT(args[2]);

    ret = cs_option(handle, type, value);

    return _CS_INT(ret);
}

static emacs_value
Fcall_cs_errno(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    cs_err ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);

    ret = cs_errno(handle);

    return _CS_INT(ret); 
}

static emacs_value
Fcall_cs_strerror(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    const char *ret;
    cs_err code = (cs_err)_CS_PULL_INT(args[0]);

    ret = cs_strerror(code);
    if (ret != NULL) {
        return _CS_STRING(ret, strlen(ret));
    }
    else {
        return _CS_NIL();
    }
}

static emacs_value
Fcall_cs_reg_name(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    const char *ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);
    unsigned int reg_id = (unsigned int)_CS_PULL_INT(args[1]);

    ret = cs_reg_name(handle, reg_id);
    if (ret != NULL) {
        return _CS_STRING(ret, strlen(ret));
    } else {
        return _CS_NIL();
    }
}

static emacs_value
Fcall_cs_insn_name(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    const char *ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);
    unsigned int insn_id = (unsigned int)_CS_PULL_INT(args[1]);
    
    ret = cs_insn_name(handle, insn_id);
    if (ret != NULL) {
        return _CS_STRING(ret, strlen(ret));
    } else {
        return _CS_NIL();
    }
}

static emacs_value
Fcall_cs_group_name(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    const char *ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);
    unsigned int group_id = (unsigned int)_CS_PULL_INT(args[1]);
    
    ret = cs_group_name(handle, group_id);
    if (ret != NULL) {
        return _CS_STRING(ret, strlen(ret));
    } else {
        return _CS_NIL();
    }
}

static emacs_value
Fcall_cs_disasm(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    size_t ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);
    uint8_t *code;
    emacs_value code_vector = args[1];
    size_t code_size = (size_t)_CS_VEC_SIZE(args[1]); 
    uint64_t address = (uint64_t)_CS_PULL_INT(args[2]);
    size_t count = (size_t)_CS_PULL_INT(args[3]);
    cs_insn *insn; 
    emacs_value cs_insn_list_list = _CS_NIL();
    
    code = malloc(code_size); 
    if (code == NULL) {
        /* no cs_errno() available here */
        return _CS_NIL();
    }
    
    /* move vector into code buf */
    for (int i = 0; i < code_size; i ++) {
        *(code+i) = (uint8_t)_CS_PULL_INT(_CS_VEC_GET(code_vector, i));
    }
    
    ret = cs_disasm(handle, code, code_size, address, count, &insn); 
    
    free(code); 

    if (ret == 0) {
        /* cs_errno() available */ 
        return _CS_NIL();
    }
    
    /* we'll build a list of insn lists ... in reverse so the cons order is right */
    for (int i = ret - 1; i >= 0; i --) {
        emacs_value cs_insn_args[6];
        emacs_value cs_insn_list;
        emacs_value cs_opcode_list = _CS_NIL();
        
        /*  skipping cs_detail for now */
        cs_insn_args[0] = _CS_INT(insn[i].id);
        cs_insn_args[1] = _CS_INT(insn[i].address);
        cs_insn_args[2] = _CS_INT(insn[i].size);
        /* turn opcode array into list of integers */ 
        for (int x = insn[i].size - 1; x >= 0; x --) {
            if (x == insn[i].size - 1) {
                emacs_value list_args[1];
                
                list_args[0] = _CS_INT((uint8_t)insn[i].bytes[x]);
                cs_opcode_list = _CS_FUNCALL("list", list_args); 
            } else {
                emacs_value cons_args[2];
                
                cons_args[0] = _CS_INT((uint8_t)insn[i].bytes[x]);
                cons_args[1] = cs_opcode_list;
                cs_opcode_list = _CS_FUNCALL("cons", cons_args); 
            }
        }
        cs_insn_args[3] = cs_opcode_list; 
        cs_insn_args[4] = _CS_STRING(insn[i].mnemonic, strlen(insn[i].mnemonic));
        cs_insn_args[5] = _CS_STRING(insn[i].op_str, strlen(insn[i].op_str));
        cs_insn_list = _CS_FUNCALL("list", cs_insn_args);
        if (i == ret - 1) {
            /* init a list of lists with the first insn */
            emacs_value list_args[1];
            
            list_args[0] = cs_insn_list;
            cs_insn_list_list = _CS_FUNCALL("list", list_args); 
        } 
        else {
            /* cons to result list */
            emacs_value cons_args[2];
            
            cons_args[0] = cs_insn_list;
            cons_args[1] = cs_insn_list_list;
            cs_insn_list_list = _CS_FUNCALL("cons", cons_args);
        } 
    }
    
    /* we're done at the native layer with this stuff, so free it */
    cs_free(insn, ret);
    
    return cs_insn_list_list;
}

/* bind c_func (native) to e_func (elisp) */
static void
bind(emacs_env *env, emacs_value (*c_func) (emacs_env *env,
                                            ptrdiff_t nargs,
                                            emacs_value args[],
                                            void *) EMACS_NOEXCEPT,
     const char *e_func,
     ptrdiff_t min_arity,
     ptrdiff_t max_arity,
     const char *doc,
     void *data)
{
    emacs_value fset_args[2];
    
    fset_args[0] = _CS_INTERN(e_func);
    fset_args[1] = _CS_MAKE_FUNC(min_arity, max_arity, c_func, doc, data);
    _CS_FUNCALL("fset", fset_args);
}

int
emacs_module_init(struct emacs_runtime *ert)
{
    emacs_env *env = ert->get_environment(ert); 
    
    bind(env,
        Fcall_cs_version, "capstone--cs-version", 0, 0, 
        "Return combined cs api version",
        NULL); 
    
    bind(env,
        Fcall_cs_support, "capstone--cs-support", 1, 1, 
        "Check cs for enabled support of ARCH",
        NULL); 
    
    bind(env,
        Fcall_cs_open, "capstone--cs-open", 2, 2, 
        "Initialize cs handle to ARCH and MODE",
        NULL);

    bind(env,
        Fcall_cs_close, "capstone--cs-close", 1, 1, 
        "Close cs handle (careful, frees internals)",
        NULL);

    bind(env,
        Fcall_cs_option, "capstone--cs-option", 3, 3, 
        "Set option on cs HANDLE of TYPE and VALUE",
        NULL); 
   
    bind(env,
        Fcall_cs_errno, "capstone--cs-errno", 1, 1, 
        "Report the last cs error from HANDLE",
        NULL); 

    bind(env,
        Fcall_cs_strerror, "capstone--cs-strerror", 1, 1, 
        "Return a string describing given error CODE",
        NULL); 

    bind(env,
        Fcall_cs_reg_name, "capstone--cs-reg-name", 2, 2, 
        "Using cs HANDLE return string name of REGISTER_ID",
        NULL); 
    
    bind(env,
        Fcall_cs_insn_name ,"capstone--cs-insn-name", 2, 2, 
        "Using cs HANDLE return string name of INSN_ID",
        NULL); 
    
    bind(env,
        Fcall_cs_group_name, "capstone--cs-group-name", 2, 2,
        "Using cs HANDLE return string name of GROUP_ID",
        NULL); 
    
    bind(env,
        Fcall_cs_disasm, "capstone--cs-disasm", 4, 4,
        "Using cs HANDLE disassemble vector CODE labeled as starting at ADDRESS for COUNT number of instructions (0 for all)",
        NULL); 

    /* 
     * NOTE: not supporting the detail API right now, this includes:
     * 
     * cs_op_index, cs_op_count, cs_reg_write, cs_reg_read, cs_insn_group
     *
     * will get to that on another weekend, don't need it right this second
     */

    emacs_value provide_args[1];
    
    provide_args[0] = _CS_INTERN("capstone-core");
    _CS_FUNCALL("provide", provide_args); 

#undef _CS_INT
#undef _CS_PULL_INT
#undef _CS_STRING
#undef _CS_VEC_SIZE
#undef _CS_VEC_GET
#undef _CS_INTERN
#undef _CS_NIL
#undef _CS_MAKE_FUNC
    
    return 0;
}
