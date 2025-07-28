# memleak_catch

memleak_catch is a tool that monitors memory allocations and leaks done by the PHP extensions in the runtime. It uses eBPF (extended Berkeley Packet Filter) technology. For detailed explanation of how the tool works, visit [here](https://medium.com/@psy_maestro/ebpf-based-php-extension-memory-leak-runtime-monitoring-9a88cbe58e76).

It traces Uprobes malloc, calloc, realloc, free and Uretprobes malloc, calloc, and realloc. It creates a file in the currently working directory named output_{day}_{month}_{hour}_{minute}.txt and the output is like the following: 
![sample output](memleak_catch_output.png)

It doesn't trace PHP's specific functions like emalloc, ecalloc, erealloc, or efree. These functions generally do not call system's memory allocation functions. Therefore, if you used emalloc, ecalloc, erealloc, or efree functions in your PHP extension, it won't log those functions. 

## Building and Running
- make install
- memleak_catch (while php-fpm running)

## Notes
- php --enable-fpm ile compile edilmeli
- php-fpm bizim monitoring uygulamasından sonra başlatıldıysa o process'leri yakalayamıyor
- sadece bizim yazdığımız extension içindeki malloc'ları tespit ediyor, sistem malloc'larını filtreliyor dikkate almıyor
- allocate edilen malloc herhangi bir yerde kullanılmıyorsa OS onu allocate etmiyor. Dolayısıyla yakalayamıyoruz ama allocation olmadığı için önemli değil (Bunu allocation'ın commit edilmemesi şeklinde de düşünebiliriz)
