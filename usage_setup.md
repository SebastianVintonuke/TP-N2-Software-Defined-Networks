# Instalar python2 del binario
```bash
sudo apt update

sudo apt install build-essential checkinstall

sudo apt install libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev


sudo wget https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz
sudo tar -xvf Python-2.7.18.tgz

cd Python-2.7.18

sudo ./configure --enable-optimizations
sudo make
sudo make install 
```

# Hacer virtualenv
```bash
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
sudo python2.7 get-pip.py 

pip2 install virtualenv	

virtualenv -p python2.7 tp2_env
```
Despues para correrlo

```bash
source tp2_env/bin/activate
```


Para pox con python3 parece funcionar el clone del repo como tal.


# POX runnables?
Sample sencillo
```bash
./pox.py --verbose samples.spanning_tree
```

# Chatgpt
Chatgpt tiro esto con log level.
```bash
python ./pox.py log.level --DEBUG openflow.discovery samples.spanning_tree
```

o con python3

```bash
python3 ./pox.py log.level --DEBUG openflow.discovery samples.spanning_tree
```

mas legible?
```bash
python3 ./pox.py --verbose openflow.discovery samples.spanning_tree
```

Por default parece openflow.discovery es seteado.
```bash
python3 ./pox.py --verbose samples.spanning_tree
```




## Con el firewall , copiar el firewall.py a la carpeta sample de pox
```bash
python ./pox.py --verbose samples.spanning_tree samples.firewall
```

## Creando carpeta 'redes' en pox , y haciendo soft link a la carpeta del tp con el firewall
```bash
python ./pox.py --verbose samples.spanning_tree redes.tp2.firewall
```

o
```bash

python3 ./pox.py --verbose samples.spanning_tree redes.tp2.firewall
```

## Ejemplo crear soft link
```bash
mkdir <ruta a pox>/pox/pox/redes
# agregar __init__.py
ln -s <ruta a redes?>/tp2 <ruta a pox>/pox/pox/redes/tp2
```

# MININET

simple del pdf del enunciado
```bash
sudo mn --topo single,3 --mac --arp --switch ovsk --controller remote
```

esto no existe, habria q tener un fattree en algun lado.
```bash
sudo mn --custom ~/mininet/custom/fattree.py --topo fattree --mac --arp --switch ovsk --controller remote
```


From linear top, del tp1 parte fragmentacion
```bash
sudo mn --custom ./linear_ends_topo.py --topo linends,1,800 --link tc --mac --arp --switch ovsk --controller remote
```


Para una topologia dinamica, agregada al repo
```bash
sudo mn --custom ./dynamic_topology.py --topo dynamicTopology,0 --mac --arp --switch ovsk --controller remote
```
