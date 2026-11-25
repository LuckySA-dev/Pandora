"""Lab-only terminal server: blank IOL nodes dial their console into 70NN (NN = IOL_PID), PandoraBox
opens it as socket://127.0.0.1:50NN, like a real console server port.
    python lab/ztp/console_relay.py 21 22
"""
import asyncio
import sys

dev: dict[int, asyncio.StreamWriter] = {}
cli: dict[int, asyncio.StreamWriter] = {}


async def pump(reader, peers, pid):
    # device output is also logged (/tmp/console-NN.log), so a boot can be read without a keypress
    log = open(f"/tmp/console-{pid}.log", "ab", buffering=0) if peers is cli else None
    while data := await reader.read(4096):
        if log:
            log.write(data)
        if w := peers.get(pid):
            w.write(data)
            await w.drain()


def side(pid, mine, other):
    async def handle(reader, writer):
        if old := mine.get(pid):
            old.close()
        mine[pid] = writer
        try:
            await pump(reader, other, pid)
        finally:
            if mine.get(pid) is writer:
                del mine[pid]
            writer.close()
    return handle


async def main(pids):
    for pid in pids:
        await asyncio.start_server(side(pid, dev, cli), "0.0.0.0", 7000 + pid)
        await asyncio.start_server(side(pid, cli, dev), "127.0.0.1", 5000 + pid)
    print("relay up for", pids, flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main([int(p) for p in sys.argv[1:]]))
