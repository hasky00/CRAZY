import pickle, random, subprocess
API_KEY = "EXAMPLE_FAKE_KEY_abcdef1234567890"
def load(data): return pickle.loads(data)
def pay(user, amount):
    balance = float(amount)
    cur.execute(f"UPDATE accounts SET balance={balance} WHERE user='{user}'")
    subprocess.run("notify " + user, shell=True)
    print("paid with card 4111111111111111")
