import md5, timing, mmap, os

def benchmark_md5_1(file):
    timing.start()
    fileob = open(file)
    fileno = fileob.fileno()
    md5ob = md5.new(mmap.mmap(fileno, os.fstat(fileno)[6],
                              prot=mmap.PROT_READ))
    sum = md5ob.hexdigest()
    fileob.close()
    timing.finish()
    print timing.milli()
    return sum

def benchmark_md5_2(file):
    timing.start()
    fileob = open(file)
    md5ob = md5.new(fileob.read())
    sum = md5ob.hexdigest()
    fileob.close()
    timing.finish()
    print timing.milli()
    return sum

def benchmark_md5(file):
    print benchmark_md5_1(file)
    print benchmark_md5_2(file)
    print benchmark_md5_1(file)
    print benchmark_md5_2(file)
