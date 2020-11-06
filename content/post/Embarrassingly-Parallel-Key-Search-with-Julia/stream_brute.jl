mask32 = 0xffffffff
mask64 = 0xffffffffffffffff


function encryptblock(block::UInt64, password::UInt64, rounds)
    
    password = password * 0x8D1B4035 
    password = password

    le = UInt32(0)
    ri = UInt32(0)

    
    le = block >> 32
    ri = block & mask32
    
    for i = 1:rounds
        # println("le: $i $le")
        le = (le << 19) | (le >> 13)
        le &= mask32
        le ⊻= password >> 32
        le ⊻= ri

        tmp = ri 
        ri = le 
        le = tmp 

        password = (password * 3 + 0x5812CE48F3A68B09)
    end

    ciphertext = le << 32 
    ciphertext |=  ri 

    return ciphertext

end

function decryptblock(block::UInt64, password::Int64, rounds)
    
    password = UInt64(password * 0x8D1B4035)
    pws = Array(UInt64, rounds)

    pws[1] = password
    
    for i = 2:round
        pws[i] = pws[i - 1] * 3 + 0x5812CE48F3A68B09
    end

    le = block >> 32 
    ri = block & mask32

    for i = 1:rounds
        tmp = ri
        ri = le 
        le = tmp 

        le ⊻= ri
        le ⊻= pws[rounds  i] >> 32 
        le = (le << 19) | (le >> 13)
        le &= mask32
    end

    plaintext = (le << 32 ) || ri 

    return plaintext
    
end


known_pt = UInt64(0x4141414141414141)
known_ct = UInt64(0x212ced02de0ba3d5)

function break_routine(start)
    println("Start at $start")
    pw = UInt64(0)
    
    p1 = UInt8(start)
    for p2 = 0:256
        for p3 = 0:256
            for p4 = 0:256
                pw =  UInt64(p1) << 24
                pw |= UInt64(p2) << 16
                pw |= UInt64(p3) << 8
                pw |= UInt64(p4)
                
                temp = encryptblock(known_pt, pw, 16)
                if temp == known_ct
                    println("Found: $pw")
                    exit(0)
                end
            end
        end
    end

    println("Complete at $start")
end


# Check with Python, make sure it correct
key = UInt64(0x44424344)
ciphertext = encryptblock(known_pt, key, 16)
if ciphertext != 4357724131518883252
    println("WRONG!!! Check the code")
    exit(1)
end

println("PASS, start to brute... .")
# asyncmap(break_routine, range(0, length=256, step=1), ntasks=12)
println(Threads.nthreads())
Threads.@threads for i = 0:255
    break_routine(i)
end

# export JULIA_NUM_THREADS=12
# julia stream_brute.jl

