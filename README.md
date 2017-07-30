<img src="http://angr.io/img/angry_face.png" width = "100" height = "100" alt="图片名称" /><img src="http://angr.io/img/angry_face.png" width = "100" height = "100" alt="图片名称" /><img src="http://angr.io/img/angry_face.png" width = "100" height = "100" alt="图片名称" /><img src="http://angr.io/img/angry_face.png" width = "100" height = "100" alt="图片名称" /> <img src="http://angr.io/img/angry_face.png" width = "100" height = "100" alt="图片名称" /><img src="http://angr.io/img/angry_face.png" width = "100" height = "100" alt="图片名称" /><img src="http://angr.io/img/angry_face.png" width = "100" height = "100" alt="图片名称" />
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
  
