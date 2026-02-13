@echo off
echo Starting dependency check > fix_log.txt
echo Installing requirements... >> fix_log.txt
python -m pip install -r requirements.txt >> fix_log.txt 2>&1
echo Checking sqlalchemy... >> fix_log.txt
python -c "import sqlalchemy; print('SQLAlchemy is working')" >> fix_log.txt 2>&1
echo Done. >> fix_log.txt
