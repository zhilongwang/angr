
# angr
Read the code of angr
### 1. Angr highly recommend using a python virtual environment to install and use angr. 
  #virtualenv
 
  ```bash
  (sudo) pip install virtualenv
  ```

  #virtualenvwrapper
  ```Bash
  (sudo) pip install virtualenvwrapper
  ```

### 2. virthalenv configure.
  #add envionment variables to .bashrc
   ``` bash
   export WORKON_HOME=$HOME/.virtualenvs
   export PROJECT_HOME=$HOME/workspace
   source /usr/local/bin/virtualenvwrapper.sh
   ```
   
   #source
   ```bash
   source ~/.bashrc
   ```
   
 ### 3. create a python virtual environment for angr
  #
  ```bash
  mkvirtualenv angr
  ```
  #related bash you may need
  ```bash
  workon angr
  deactivate
  rmvirtualenv angr
  mkproject mic
  mktmpenv
  lsvirtualenv
  lssitepackages
  ```
 ### 4. install angr
  #
  ```bash
  (sudo) pip install angr
  ```
 ### 5. problem you may encounter
  #need libffi
  ```bash
  wget ftp://sourceware.org/pub/libffi/libffi-3.2.1.tar.gz
  tar -zxvf libffi-3.2.1.tar.gz 
  ./configure
  make
  sudo make install
  ```
  
  #need glib-2.0
  ```bash
  sudo apt-get install libglib2.0-dev
  ```
  #unrecognized command line option '-std=c++11'
  ```bash
  sudo add-apt-repository ppa:ubuntu-toolchain-r/test     sudo apt-get update;   
  sudo apt-get install gcc-4.8 g++-4.8     
  sudo update-alternatives --remove-all gcc   
  sudo update-alternatives --remove-all g++  
  sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 20  
  sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.8 20  
  sudo update-alternatives --config gcc  
  sudo update-alternatives --config g++   
  ```
  
  #IOError: [Errno 2] No such file or directory: '/usr/local/lib/python2.7/dist-packages/angr/analyses/identifier/../example_flag_page'
    
    ```bash
    1.wget https://github.com/angr/angr/raw/master/angr/analyses/example_flag_page
    2.mv example_flag_page /...[analyses].
    ```
