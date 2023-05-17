from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist

import re

class Torhistory(interfaces.plugins.PluginInterface):
    """Find Deep web onion address in memory. You can disignate Tor browser pid"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    strings_pattern = re.compile(b'[\x20-\x7E]+')
    history_pattern = re.compile(b'https?\:\/\/[a-z,A-Z,0-9]+\.onion[a-zA-Z0-9\.\/\?\:@\-_=#]*') 

    @classmethod
    def get_requirements(self):
        return [
            requirements.TranslationLayerRequirement(
                name='primary',
                description='Memory layer for the kernel',
                architectures=['Intel32', 'Intel64']
            ),
            requirements.SymbolTableRequirement(
                name='nt_symbols',
                description='Windows kernel symbols'
            ),
            requirements.PluginRequirement(
                name='pslist',
                plugin=pslist.PsList,
                version=(2, 0, 0)
            ),
            requirements.IntRequirement(
                name='pid',
                description='Process ID to include (all other processes are excluded)',
                optional=True
            ),
        ]

    def _generator(self, procs):
        num = 0

        for proc in procs:
            for vad in proc.get_vad_root().traverse():
                try:
                    proc_layer_name = proc.add_process_layer()
                    proc_layer = self.context.layers[proc_layer_name]

                    data_size = vad.get_end() - vad.get_start()
                    data = proc_layer.read(vad.get_start(), data_size, pad=True)
                    
                    for string in self.strings_pattern.findall(data):
                        for url in self.history_pattern.findall(string):
                            yield (
                                0,                        # level
                                (
                                    num,
                                    url.decode()          # url
                                )
                            )
                            num += 1
                            with self.open('Torbrowser_history.csv') as file_handle:
                                file_handle.write(url)
                                
                except MemoryError:
                    comment  =  """
                                Error occurred!! 
                                """
                    pass

    def run(self):
        return renderers.TreeGrid(
            [
                # colums name and type
                ('no',    int),
                ('url',   str)
            ],
            self._generator(
                pslist.PsList.list_processes(
                    self.context,
                    self.config['primary'],
                    self.config['nt_symbols'],
                    filter_func = pslist.PsList.create_pid_filter(
                        [self.config.get('pid', None)]
                    )
                )
            )
        )

