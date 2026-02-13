@echo off
echo Starting dependency check with 'py' > fix_log_py.txt
echo Installing requirements... >> fix_log_py.txt
py -m pip install -r requirements.txt >> fix_log_py.txt 2>&1
echo Checking sqlalchemy... >> fix_log_py.txt
py -c "import sqlalchemy; print('SQLAlchemy is working')" >> fix_log_py.txt 2>&1
echo Done. >> fix_log_py.txt
