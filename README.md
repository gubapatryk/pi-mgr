![image](https://user-images.githubusercontent.com/46055596/111359007-48823100-868b-11eb-9b9b-53e5a3922fff.png)
![image](https://user-images.githubusercontent.com/46055596/111359038-51730280-868b-11eb-8e0c-cc30514ad1bd.png)
![image](https://user-images.githubusercontent.com/46055596/111359044-546df300-868b-11eb-98f0-f8eecde29163.png)


Przy pierwszym uruchomieniu kontener z aplikacją (flask) trzeba ręcznie zrestartować. 
Aplikacja nie może od razu się połączyć z bazą danych, ponieważ utworzenie tabel w MySQL zajmuje trochę czasu, więc wyrzucany jest błąd.

    docker restart flask
