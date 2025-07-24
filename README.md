# memleak_catch

## Building and Running
- make install
- memleak_catch (while php-fpm running)

## Notes
- php --enable-fpm ile compile edilmeli
- php-fpm bizim monitoring uygulamasından sonra başlatıldıysa o process'leri yakalayamıyor
- sadece bizim yazdığımız extension içindeki malloc'ları tespit ediyor, sistem malloc'larını filtreliyor dikkate almıyor
- allocate edilen malloc herhangi bir yerde kullanılmıyorsa OS onu allocate etmiyor. Dolayısıyla yakalayamıyoruz ama allocation olmadığı için önemli değil (Bunu allocation'ın commit edilmemesi şeklinde de düşünebiliriz)
