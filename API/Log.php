<?php

namespace Service\API;

use Monolog\Logger as MonologLogger;
use Illuminate\Log\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Formatter\LineFormatter;

trait Log
{
    protected $_logger = null;

    protected function _initLogger($ident, $folder = '')
    {
        $monolog_logger = new MonologLogger($ident);

        $stream_handler = null;
        if (function_exists('posix_isatty') && posix_isatty(STDOUT)) {
            $stream_handler = new StreamHandler('php://stderr', MonologLogger::DEBUG);
        } else {
            $path = ($folder ? $folder . DIRECTORY_SEPARATOR : '') . $ident;
            $stream_handler = new RotatingFileHandler(
                storage_path() . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . "{$path}.log",
                10,
                MonologLogger::DEBUG
            );
        }

        $stream_handler->setFormatter(new LineFormatter('[%datetime%] %channel%.%level_name%: %message%' . PHP_EOL, null, true));
        $monolog_logger->pushHandler($stream_handler);

        $this->_logger = new Logger($monolog_logger);
    }

    protected function _log(string $msg, $extra = [])
    {
        $this->_logger->info($msg);
        if (!empty($extra)) {
            $this->_logger->info("附加说明:" . PHP_EOL . print_r($extra, true));
        }
    }
}
