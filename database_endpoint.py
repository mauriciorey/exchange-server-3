from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine, select, MetaData, Table
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only

from models import Base, Order, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

#These decorators allow you to use g.session to access the database inside the request code
@app.before_request
def create_session():
    g.session = scoped_session(DBSession) #g is an "application global" https://flask.palletsprojects.com/en/1.1.x/api/#application-globals

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    g.session.commit()
    g.session.remove()

"""
-------- Helper methods (feel free to add your own!) -------
"""

def log_message(d)
    # Takes input dictionary d and writes it to the Log table
    pass

"""
---------------- Endpoints ----------------
"""
    
@app.route('/trade', methods=['POST'])
def trade():
    if request.method == "POST":
        content = request.get_json(silent=True)
        print( f"content = {json.dumps(content)}" )
        columns = [ "sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform" ]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            log_message(content)
            return jsonify( False )
            
        #Your code here
        #Note that you can access the database session using g.session
        sig = content['sig']
        pk = content['payload']['sender_pk']
        platform = content['payload']['platform']
        payload = content['payload']
        payload2= json.dumps(payload)
        order = {'sender_pk': payload['sender_pk'],
             'receiver_pk': payload['receiver_pk'],
            'buy_currency': payload['buy_currency'],
            'sell_currency': payload['sell_currency'],
            'buy_amount': payload['buy_amount'],
            'sell_amount': payload['sell_amount'],
            'signature':sig
            }
        order_obj = Order( sender_pk=order['sender_pk'],
         receiver_pk=order['receiver_pk'],
         buy_currency=order['buy_currency'], 
         sell_currency=order['sell_currency'], 
         buy_amount=order['buy_amount'], 
         sell_amount=order['sell_amount'],
         signature=order['signature'] )

        logError = {'message':payload2}
        log_obj = Log(message = logError['message'])

    
        

        result = False
        try:
            if platform == "Ethereum":
                eth_encoded_msg = eth_account.messages.encode_defunct(text=payload2)
                if (eth_account.Account.recover_message(eth_encoded_msg,signature=sig) == pk):
                    result = True
            elif platform == "Algorand":
                #result = algosdk.util.verify_bytes(message.encode('utf-8'),sig,pk)
                if algosdk.util.verify_bytes(payload2.encode('utf-8'),sig,pk):
                    result = True
            else:
                result = False
        except:
            print("verification part throw exception")
            result = False
        
        #If the signature verifies, store the signature, as well as all of the fields under the ‘payload’ in the “Order” 
        # #table EXCEPT for 'platform’.
        if result:
            g.session.add(order_obj)
            g.session.commit()
            return jsonify(order)
            

        # If the signature does not verify, do not insert the order into the “Order” table.
        # Instead, insert a record into the “Log” table, with the message field set to be json.dumps(payload).
        else:
            g.session.add(log_obj)
            g.session.commit()
            return jsonify(logError)
        

@app.route('/order_book')
def order_book():
    #Your code here
    #Note that you can access the database session using g.session
    result = []
    for x in g.session.query(Order).all():
        dict = x.__dict__
        nDic = { v : dict[v] for v in ["sender_pk","receiver_pk","buy_currency","sell_currency","buy_amount","sell_amount","signature"]}
        result.append(nDic)
        
    r2 = {"data":result}
    return jsonify(r2)

if __name__ == '__main__':
    app.run(port='5002')
